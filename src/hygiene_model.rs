//! Pure-Rust forward pass of the vendored `codehygiene` 1.58-bit ternary model (`vendor/codehygiene/weights.npz`).
//! Runs in-process with no Python or NumPy subprocess.

use crate::hygiene::Squiggle;
use flate2::read::DeflateDecoder;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::OnceLock;

const WEIGHTS_NPZ: &[u8] = include_bytes!("../vendor/codehygiene/weights.npz");

const MAX_COLS: usize = 128;
const MAX_LINES: usize = 2048;
const MAX_REL_DIST: isize = 32;
const SKETCH_DIM: usize = 40;
const THRESHOLD: f32 = 0.55;
const POW3: [u8; 5] = [1, 3, 9, 27, 81];

const SPEC: [(&str, &str); 8] = [
    ("deep_nesting", "Deep nesting; flatten with guard clauses"),
    (
        "poor_naming",
        "Over-abstracted (*Factory), cryptic short name, or magic index",
    ),
    ("noisy_comment", "Comment restates code or leaves TODO/lint noise"),
    ("swallowed_error", "Ignored error or silent fallback value"),
    ("dense_line", "Long line, chained calls, or nested ternary"),
    ("special_casing", "Stacked hardcoded special-case branches"),
    ("duplicate_block", "Duplicated logic block"),
    ("cramped_layout", "Unbroken statement wall or inconsistent indent"),
];

#[derive(Clone)]
struct Tensor {
    shape: Vec<usize>,
    data: Vec<f32>,
}

struct Weights {
    params: HashMap<String, Tensor>,
}

impl Weights {
    fn get(&self, name: &str) -> &Tensor {
        self.params.get(name).unwrap_or_else(|| panic!("missing weight {name}"))
    }
}

fn weights() -> Result<&'static Weights, String> {
    static LOADED: OnceLock<Result<Weights, String>> = OnceLock::new();
    match LOADED.get_or_init(|| load_weights(WEIGHTS_NPZ)) {
        Ok(w) => Ok(w),
        Err(e) => Err(e.clone()),
    }
}

fn u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let slice: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(slice))
}

fn u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let slice: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(slice))
}

fn inflate_entry(method: u16, compressed: &[u8]) -> Result<Vec<u8>, String> {
    match method {
        0 => Ok(compressed.to_vec()),
        8 => {
            let mut decoder = DeflateDecoder::new(compressed);
            let mut buf = Vec::new();
            decoder
                .read_to_end(&mut buf)
                .map_err(|e| format!("weights.npz: deflate failed: {e}"))?;
            Ok(buf)
        }
        other => Err(format!("weights.npz: unsupported ZIP method {other}")),
    }
}

struct CdHeader {
    method: u16,
    comp_size: usize,
    name_len: usize,
    extra_len: usize,
    comment_len: usize,
    local_off: usize,
}

fn read_cd_header(zip: &[u8], pos: usize) -> Result<CdHeader, String> {
    let err = "weights.npz: truncated CD";
    Ok(CdHeader {
        method: u16_le(zip, pos + 10).ok_or(err)?,
        comp_size: u32_le(zip, pos + 20).ok_or(err)? as usize,
        name_len: u16_le(zip, pos + 28).ok_or(err)? as usize,
        extra_len: u16_le(zip, pos + 30).ok_or(err)? as usize,
        comment_len: u16_le(zip, pos + 32).ok_or(err)? as usize,
        local_off: u32_le(zip, pos + 42).ok_or(err)? as usize,
    })
}

fn read_local_payload(zip: &[u8], hdr: &CdHeader) -> Result<Vec<u8>, String> {
    let err = "weights.npz: truncated local header";
    let l_name_len = u16_le(zip, hdr.local_off + 26).ok_or(err)? as usize;
    let l_extra_len = u16_le(zip, hdr.local_off + 28).ok_or(err)? as usize;
    let data_start = hdr.local_off + 30 + l_name_len + l_extra_len;
    let compressed = zip
        .get(data_start..data_start + hdr.comp_size)
        .ok_or("weights.npz: truncated entry data")?;
    inflate_entry(hdr.method, compressed)
}

fn read_zip_entry(zip: &[u8], pos: usize) -> Result<(String, Vec<u8>, usize), String> {
    let hdr = read_cd_header(zip, pos)?;
    let name_bytes = zip
        .get(pos + 46..pos + 46 + hdr.name_len)
        .ok_or("weights.npz: bad name")?;
    let name = std::str::from_utf8(name_bytes)
        .map_err(|_| "weights.npz: non-utf8 entry name")?
        .to_string();
    let data = read_local_payload(zip, &hdr)?;
    Ok((name, data, pos + 46 + hdr.name_len + hdr.extra_len + hdr.comment_len))
}

/// Extracts all entries from a ZIP archive via its Central Directory.
fn unzip_entries(zip: &[u8]) -> Result<HashMap<String, Vec<u8>>, String> {
    let eocd = zip
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .ok_or("weights.npz: missing ZIP end-of-central-directory")?;
    let cd_size = u32_le(zip, eocd + 12).ok_or("weights.npz: truncated EOCD")? as usize;
    let cd_offset = u32_le(zip, eocd + 16).ok_or("weights.npz: truncated EOCD")? as usize;
    let cd_end = cd_offset.saturating_add(cd_size).min(zip.len());
    let mut out = HashMap::new();
    let mut pos = cd_offset;
    while pos + 46 <= cd_end && &zip[pos..pos + 4] == b"PK\x01\x02" {
        let (name, data, next_pos) = read_zip_entry(zip, pos)?;
        out.insert(name, data);
        pos = next_pos;
    }
    Ok(out)
}

/// Strips the `.npy` header and returns the raw payload bytes.
fn npy_payload(npy: &[u8]) -> Result<&[u8], String> {
    if npy.len() < 10 || &npy[..6] != b"\x93NUMPY" {
        return Err("invalid .npy magic".into());
    }
    let (hstart, hlen) = if npy[6] == 1 {
        (10usize, u16_le(npy, 8).ok_or("truncated .npy v1 header")? as usize)
    } else {
        (12usize, u32_le(npy, 8).ok_or("truncated .npy v2 header")? as usize)
    };
    npy.get(hstart + hlen..).ok_or_else(|| "truncated .npy payload".into())
}

fn parse_shape(dims: &str) -> Result<Vec<usize>, String> {
    dims.split(',')
        .map(|d| d.trim().parse::<usize>().map_err(|_| format!("bad dim: {d}")))
        .collect()
}

fn broadcast_strides(mat_shape: &[usize], scale_shape: &[usize]) -> Vec<usize> {
    let rank = mat_shape.len();
    let mut padded = vec![1usize; rank];
    let offset = rank.saturating_sub(scale_shape.len());
    for (i, &dim) in scale_shape.iter().enumerate() {
        padded[offset + i] = dim;
    }
    let mut strides = vec![0usize; rank];
    let mut stride = 1usize;
    for i in (0..rank).rev() {
        strides[i] = if padded[i] == 1 { 0 } else { stride };
        stride *= padded[i];
    }
    strides
}

fn step_coords(coords: &mut [usize], shape: &[usize]) {
    for d in (0..shape.len()).rev() {
        coords[d] += 1;
        if coords[d] < shape[d] {
            return;
        }
        coords[d] = 0;
    }
}

/// Broadcasts `scale` onto `mat` (matching NumPy trailing-dimension broadcasting).
fn multiply_broadcast(mat: &mut [f32], mat_shape: &[usize], scale: &Tensor) {
    if scale.data.len() == 1 {
        let s = scale.data[0];
        mat.iter_mut().for_each(|v| *v *= s);
        return;
    }
    if scale.data.len() == mat.len() {
        mat.iter_mut().zip(&scale.data).for_each(|(v, &s)| *v *= s);
        return;
    }
    let strides = broadcast_strides(mat_shape, &scale.shape);
    let mut coords = vec![0usize; mat_shape.len()];
    for val in mat.iter_mut() {
        let s_idx: usize = coords.iter().zip(&strides).map(|(&c, &st)| c * st).sum();
        *val *= scale.data[s_idx];
        step_coords(&mut coords, mat_shape);
    }
}

fn parse_meta_entry(entry: &str) -> Result<(String, Vec<usize>, usize), String> {
    let mut parts = entry.split(':');
    let name = parts.next().ok_or("bad meta entry")?.to_string();
    let shape = parse_shape(parts.next().ok_or("bad meta dims")?)?;
    let count = parts
        .next()
        .ok_or("bad meta count")?
        .parse::<usize>()
        .map_err(|_| "bad meta count")?;
    Ok((name, shape, count))
}

fn parse_vec_tensors(vec_part: &str, vec_buf: &[f32]) -> Result<HashMap<String, Tensor>, String> {
    let mut vecs = HashMap::new();
    let mut offset = 0usize;
    for entry in vec_part.split(" ; ") {
        let (name, shape, count) = parse_meta_entry(entry)?;
        let data = vec_buf
            .get(offset..offset + count)
            .ok_or("vec_buf out of bounds")?
            .to_vec();
        offset += count;
        vecs.insert(name, Tensor { shape, data });
    }
    Ok(vecs)
}

fn unpack_trits(trit_buf: &[u8]) -> Vec<f32> {
    let mut flat = Vec::with_capacity(trit_buf.len() * 5);
    for &b in trit_buf {
        for &p in &POW3 {
            let digit = (((b / p) % 3 + 1) % 3) as i8 - 1;
            flat.push(f32::from(digit));
        }
    }
    flat
}

fn scale_key_for(name: &str) -> String {
    if name == "col_sum_proj" {
        "col_sum_s".to_string()
    } else if let Some(stem) = name.strip_suffix("_w") {
        format!("{stem}_s")
    } else {
        format!("{name}_s")
    }
}

fn parse_trit_tensors(
    trit_part: &str,
    flat_trits: &[f32],
    vecs: &HashMap<String, Tensor>,
) -> Result<HashMap<String, Tensor>, String> {
    let mut params = HashMap::new();
    let mut byte_offset = 0usize;
    for entry in trit_part.split(" ; ") {
        let (name, shape, packed_len) = parse_meta_entry(entry)?;
        let num_elems: usize = shape.iter().product();
        let start = byte_offset * 5;
        let mut mat = flat_trits
            .get(start..start + num_elems)
            .ok_or("trit_buf out of bounds")?
            .to_vec();
        byte_offset += packed_len;
        if let Some(scale) = vecs.get(&scale_key_for(&name)) {
            multiply_broadcast(&mut mat, &shape, scale);
        }
        params.insert(name, Tensor { shape, data: mat });
    }
    Ok(params)
}

fn npy_entry<'a>(entries: &'a HashMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8], String> {
    let raw = entries.get(name).ok_or_else(|| format!("missing {name}"))?;
    npy_payload(raw)
}

fn decode_f32_le(bytes: &[u8]) -> Vec<f32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&c| f32::from_le_bytes(c))
        .collect()
}

fn decode_utf32_le(bytes: &[u8]) -> String {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .filter_map(|&c| {
            let cp = u32::from_le_bytes(c);
            (cp != 0).then(|| char::from_u32(cp)).flatten()
        })
        .collect()
}

fn load_weights(npz: &[u8]) -> Result<Weights, String> {
    let entries = unzip_entries(npz)?;
    let trit_buf = npy_entry(&entries, "trits.npy")?;
    let vec_buf = decode_f32_le(npy_entry(&entries, "vecs.npy")?);
    let meta = decode_utf32_le(npy_entry(&entries, "meta.npy")?);

    let (trit_part, vec_part) = meta.split_once('|').ok_or("invalid meta format")?;
    let vecs = parse_vec_tensors(vec_part, &vec_buf)?;
    let flat_trits = unpack_trits(trit_buf);
    let mut params = parse_trit_tensors(trit_part, &flat_trits, &vecs)?;
    for (name, val) in vecs {
        if !name.ends_with("_s") {
            params.insert(name, val);
        }
    }
    Ok(Weights { params })
}

fn expand_tabs_2(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut col = 0usize;
    for ch in code.chars() {
        match ch {
            '\t' => {
                let spaces = 2 - (col % 2);
                out.extend(std::iter::repeat_n(' ', spaces));
                col += spaces;
            }
            '\n' | '\r' => {
                out.push(ch);
                col = 0;
            }
            _ => {
                out.push(ch);
                col += 1;
            }
        }
    }
    out
}

/// Converts raw source text into `(num_lines, MAX_COLS)` 7-bit ASCII byte grid matching Python `encode_byte_grid`.
fn encode_byte_grid(code: &str) -> (Vec<u8>, usize) {
    let expanded = expand_tabs_2(code);
    let mut lines: Vec<&str> = crate::py::splitlines(&expanded, false);
    if lines.is_empty() {
        lines.push("");
    }
    lines.truncate(MAX_LINES);
    let num_lines = lines.len();
    let mut grid = vec![0u8; num_lines * MAX_COLS];
    for (row, text) in lines.iter().enumerate() {
        let base = row * MAX_COLS;
        for (col, ch) in text.chars().take(MAX_COLS).enumerate() {
            let byte = (ch as u32).min(127) as u8;
            grid[base + col] = if byte == 0 { 32 } else { byte };
        }
    }
    (grid, num_lines)
}

#[inline]
fn relu_in_place(data: &mut [f32]) {
    for v in data.iter_mut() {
        *v = v.max(0.0);
    }
}

#[inline]
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x.clamp(-30.0, 30.0)).exp())
}

/// `out = a @ b + bias` where `a` is `(m, k)`, `b` is `(k, n)`, optional `bias` is `(n,)`.
fn matmul_add(a: &[f32], b: &[f32], bias: Option<&[f32]>, m: usize, k: usize, n: usize) -> Vec<f32> {
    let mut out = vec![0.0f32; m * n];
    for i in 0..m {
        let out_row = &mut out[i * n..(i + 1) * n];
        if let Some(bias) = bias {
            out_row.copy_from_slice(bias);
        }
        let a_row = &a[i * k..(i + 1) * k];
        for (p, &av) in a_row.iter().enumerate() {
            if av == 0.0 {
                continue;
            }
            let b_row = &b[p * n..(p + 1) * n];
            for (dst, &bv) in out_row.iter_mut().zip(b_row) {
                *dst += av * bv;
            }
        }
    }
    out
}

fn active_kernel_pairs(kernel: &Tensor, c_in: usize) -> Vec<(usize, usize)> {
    let k_size = kernel.shape[0];
    let c_out = kernel.shape[2];
    let mut active = Vec::new();
    for offset in 0..k_size {
        for ic in 0..c_in {
            let base = (offset * c_in + ic) * c_out;
            if kernel.data[base..base + c_out].iter().any(|&w| w != 0.0) {
                active.push((offset, ic));
            }
        }
    }
    active
}

fn conv1d_cell(
    cells_line: &[f32],
    w: usize,
    num_cols: usize,
    c_in: usize,
    pad: isize,
    active: &[(usize, usize)],
    kernel: &Tensor,
    dst: &mut [f32],
) {
    let c_out = dst.len();
    for &(offset, ic) in active {
        let src_w = (w as isize) + (offset as isize) - pad;
        if src_w < 0 || src_w >= num_cols as isize {
            continue;
        }
        let val = cells_line[src_w as usize * c_in + ic];
        if val == 0.0 {
            continue;
        }
        let k_base = (offset * c_in + ic) * c_out;
        let k_slice = &kernel.data[k_base..k_base + c_out];
        for (d, &kv) in dst.iter_mut().zip(k_slice) {
            *d += val * kv;
        }
    }
}

/// 1D convolution along the column axis of `cells` `(L, W, C_in)` with `kernel` `(K, C_in, C_out)` and `bias` `(C_out,)`.
fn conv1d(cells: &[f32], num_lines: usize, num_cols: usize, c_in: usize, kernel: &Tensor, bias: &Tensor) -> Vec<f32> {
    let c_out = kernel.shape[2];
    let pad = ((kernel.shape[0] - 1) / 2) as isize;
    let active = active_kernel_pairs(kernel, c_in);
    let mut out = vec![0.0f32; num_lines * num_cols * c_out];
    for l in 0..num_lines {
        let cells_line = &cells[l * num_cols * c_in..(l + 1) * num_cols * c_in];
        for w in 0..num_cols {
            let dst = &mut out[(l * num_cols + w) * c_out..(l * num_cols + w + 1) * c_out];
            dst.copy_from_slice(&bias.data);
            conv1d_cell(cells_line, w, num_cols, c_in, pad, &active, kernel, dst);
        }
    }
    out
}

/// Conv1d + ReLU + sum over columns -> `(L, C_out)`.
fn conv1d_relu_sum(
    cells: &[f32],
    num_lines: usize,
    num_cols: usize,
    c_in: usize,
    kernel: &Tensor,
    bias: &Tensor,
) -> Vec<f32> {
    let c_out = kernel.shape[2];
    let mut conv = conv1d(cells, num_lines, num_cols, c_in, kernel, bias);
    relu_in_place(&mut conv);
    sum_columns(&conv, num_lines, num_cols, c_out)
}

fn sum_columns(tensor: &[f32], num_lines: usize, num_cols: usize, dim: usize) -> Vec<f32> {
    let mut summed = vec![0.0f32; num_lines * dim];
    for l in 0..num_lines {
        let dst = &mut summed[l * dim..(l + 1) * dim];
        for c in 0..num_cols {
            let src = &tensor[(l * num_cols + c) * dim..(l * num_cols + c + 1) * dim];
            for (d, &s) in dst.iter_mut().zip(src) {
                *d += s;
            }
        }
    }
    summed
}

/// Concatenates slices row-by-row for `rows` rows.
fn concat_last(rows: usize, parts: &[(&[f32], usize)]) -> Vec<f32> {
    let total_dim: usize = parts.iter().map(|(_, d)| *d).sum();
    let mut out = Vec::with_capacity(rows * total_dim);
    for r in 0..rows {
        for &(slice, dim) in parts {
            out.extend_from_slice(&slice[r * dim..(r + 1) * dim]);
        }
    }
    out
}

fn l2_norm_rows(src: &[f32], rows: usize, dim: usize, eps: f32) -> Vec<f32> {
    let mut out = vec![0.0f32; rows * dim];
    for r in 0..rows {
        let row = &src[r * dim..(r + 1) * dim];
        let norm = (row.iter().map(|&v| v * v).sum::<f32>() + eps).sqrt();
        let dst = &mut out[r * dim..(r + 1) * dim];
        for (d, &v) in dst.iter_mut().zip(row) {
            *d = v / norm;
        }
    }
    out
}

fn causal_prefix(input: &[f32], w_causal: &Tensor, num_lines: usize, dim: usize) -> Vec<f32> {
    let stride = MAX_COLS * dim;
    let mut out = vec![0.0f32; num_lines * stride];
    for l in 0..num_lines {
        let block = matmul_add(
            &w_causal.data,
            &input[l * stride..(l + 1) * stride],
            None,
            MAX_COLS,
            MAX_COLS,
            dim,
        );
        out[l * stride..(l + 1) * stride].copy_from_slice(&block);
    }
    out
}

struct AttnContext<'a> {
    q_proj: &'a [f32],
    k_proj: &'a [f32],
    v_proj: &'a [f32],
    b_rel: &'a [f32],
    num_lines: usize,
    q_dim: usize,
    v_dim: usize,
    head_dim: usize,
    v_head_dim: usize,
    scale: f32,
}

fn attend_head_line(
    ctx: &AttnContext<'_>,
    i: usize,
    h_off: usize,
    vh_off: usize,
    sink_logit: f32,
    logits: &mut [f32],
    dst: &mut [f32],
) {
    let qi = &ctx.q_proj[i * ctx.q_dim + h_off..i * ctx.q_dim + h_off + ctx.head_dim];
    let mut max_l = sink_logit;
    for j in 0..ctx.num_lines {
        let kj = &ctx.k_proj[j * ctx.q_dim + h_off..j * ctx.q_dim + h_off + ctx.head_dim];
        let dot: f32 = qi.iter().zip(kj).map(|(&a, &b)| a * b).sum();
        let rel_idx = ((j as isize - i as isize).clamp(-MAX_REL_DIST, MAX_REL_DIST) + MAX_REL_DIST) as usize;
        let l = dot / ctx.scale + ctx.b_rel[rel_idx];
        logits[j] = l;
        max_l = max_l.max(l);
    }
    logits[ctx.num_lines] = sink_logit;
    let mut sum_exp = 0.0f32;
    for l in logits.iter_mut() {
        *l = (*l - max_l).exp();
        sum_exp += *l;
    }
    for (j, &exp_w) in logits.iter().enumerate().take(ctx.num_lines) {
        let w = exp_w / sum_exp;
        if w == 0.0 {
            continue;
        }
        let vj = &ctx.v_proj[j * ctx.v_dim + vh_off..j * ctx.v_dim + vh_off + ctx.v_head_dim];
        for (d, &val) in dst.iter_mut().zip(vj) {
            *d += w * val;
        }
    }
}

fn sink_attn(w: &Weights, layer: &str, state: &[f32], num_lines: usize, d_model: usize) -> Vec<f32> {
    let wq = w.get(&format!("attn{layer}_wq"));
    let wk = w.get(&format!("attn{layer}_wk"));
    let wv = w.get(&format!("attn{layer}_wv"));
    let wo = w.get(&format!("attn{layer}_wo"));
    let b_rel = w.get(&format!("attn{layer}_brel"));
    let b_sink = w.get(&format!("attn{layer}_bsink"));

    let num_heads = b_sink.shape[0];
    let q_dim = wq.shape[1];
    let v_dim = wv.shape[1];
    let head_dim = q_dim / num_heads;
    let v_head_dim = v_dim / num_heads;
    let rel_stride = b_rel.shape[1];

    let q_proj = matmul_add(state, &wq.data, None, num_lines, d_model, q_dim);
    let k_proj = matmul_add(state, &wk.data, None, num_lines, d_model, q_dim);
    let v_proj = matmul_add(state, &wv.data, None, num_lines, d_model, v_dim);

    let mut merged = vec![0.0f32; num_lines * v_dim];
    let mut logits = vec![0.0f32; num_lines + 1];

    for (h, &sink_logit) in b_sink.data.iter().enumerate().take(num_heads) {
        let ctx = AttnContext {
            q_proj: &q_proj,
            k_proj: &k_proj,
            v_proj: &v_proj,
            b_rel: &b_rel.data[h * rel_stride..(h + 1) * rel_stride],
            num_lines,
            q_dim,
            v_dim,
            head_dim,
            v_head_dim,
            scale: (head_dim as f32).sqrt(),
        };
        let h_off = h * head_dim;
        let vh_off = h * v_head_dim;
        for i in 0..num_lines {
            let dst = &mut merged[i * v_dim + vh_off..i * v_dim + vh_off + v_head_dim];
            attend_head_line(&ctx, i, h_off, vh_off, sink_logit, &mut logits, dst);
        }
    }
    matmul_add(&merged, &wo.data, None, num_lines, v_dim, wo.shape[1])
}

fn embed_grid(w: &Weights, grid: &[u8], num_lines: usize) -> (Vec<f32>, usize) {
    let tok_emb = w.get("tok_emb");
    let col_emb = w.get("col_emb");
    let emb_dim = tok_emb.shape[1];
    let mut emb = vec![0.0f32; num_lines * MAX_COLS * emb_dim];
    for l in 0..num_lines {
        for c in 0..MAX_COLS {
            let tok = grid[l * MAX_COLS + c] as usize;
            let dst = &mut emb[(l * MAX_COLS + c) * emb_dim..(l * MAX_COLS + c + 1) * emb_dim];
            let t_row = &tok_emb.data[tok * emb_dim..(tok + 1) * emb_dim];
            let c_row = &col_emb.data[c * emb_dim..(c + 1) * emb_dim];
            for ((d, &tv), &cv) in dst.iter_mut().zip(t_row).zip(c_row) {
                *d = tv + cv;
            }
        }
    }
    (emb, emb_dim)
}

/// Block 0: byte/column embeddings + causal quote/comment masks -> cells `(L, W, C)`.
fn encode_cells(w: &Weights, grid: &[u8], num_lines: usize) -> (Vec<f32>, usize) {
    let total_cells = num_lines * MAX_COLS;
    let (emb, emb_dim) = embed_grid(w, grid, num_lines);

    let pre_w = w.get("pre_conv3_w");
    let lex_dim = pre_w.shape[2];
    let mut lex = conv1d(&emb, num_lines, MAX_COLS, emb_dim, pre_w, w.get("pre_conv3_b"));
    relu_in_place(&mut lex);

    let lex_cat = concat_last(total_cells, &[(&emb, emb_dim), (&lex, lex_dim)]);
    let pref1_proj = w.get("pref1_proj");
    let pref1_dim = pref1_proj.shape[1];
    let pref1_in = matmul_add(
        &lex_cat,
        &pref1_proj.data,
        None,
        total_cells,
        emb_dim + lex_dim,
        pref1_dim,
    );
    let prefix1 = causal_prefix(&pref1_in, w.get("W_causal1"), num_lines, pref1_dim);

    let gate1_in = concat_last(total_cells, &[(&emb, emb_dim), (&lex, lex_dim), (&prefix1, pref1_dim)]);
    let gate1_w = w.get("gate1_w");
    let gate_dim = gate1_w.shape[1];
    let mut gates = matmul_add(
        &gate1_in,
        &gate1_w.data,
        Some(&w.get("gate1_b").data),
        total_cells,
        emb_dim + lex_dim + pref1_dim,
        gate_dim,
    );
    relu_in_place(&mut gates);

    let pref2_proj = w.get("pref2_proj");
    let pref2_dim = pref2_proj.shape[1];
    let pref2_in = matmul_add(&gates, &pref2_proj.data, None, total_cells, gate_dim, pref2_dim);
    let prefix2 = causal_prefix(&pref2_in, w.get("W_causal2"), num_lines, pref2_dim);

    let fuse_in = concat_last(
        total_cells,
        &[
            (&emb, emb_dim),
            (&lex, lex_dim),
            (&gates, gate_dim),
            (&prefix2, pref2_dim),
        ],
    );
    let col_fuse_w = w.get("col_fuse_w");
    let cell_dim = col_fuse_w.shape[1];
    let mut cells = matmul_add(
        &fuse_in,
        &col_fuse_w.data,
        Some(&w.get("col_fuse_b").data),
        total_cells,
        emb_dim + lex_dim + gate_dim + pref2_dim,
        cell_dim,
    );
    relu_in_place(&mut cells);
    (cells, cell_dim)
}

fn encode_sketches(w: &Weights, cells: &[f32], num_lines: usize, cell_dim: usize) -> (Vec<f32>, Vec<f32>, usize) {
    let sketch_w = w.get("sketch_w");
    let raw = conv1d_relu_sum(cells, num_lines, MAX_COLS, cell_dim, sketch_w, w.get("sketch_b"));
    let total = sketch_w.shape[2];
    let b_dim = total - SKETCH_DIM;
    let clamped: Vec<f32> = raw.iter().map(|&v| v.clamp(0.0, 1.0)).collect();
    let mut a = Vec::with_capacity(num_lines * SKETCH_DIM);
    let mut b = Vec::with_capacity(num_lines * b_dim);
    for l in 0..num_lines {
        let row = &clamped[l * total..(l + 1) * total];
        a.extend_from_slice(&row[..SKETCH_DIM]);
        b.extend_from_slice(&row[SKETCH_DIM..]);
    }
    (
        l2_norm_rows(&a, num_lines, SKETCH_DIM, 2.5),
        l2_norm_rows(&b, num_lines, b_dim, 2.5),
        b_dim,
    )
}

/// Block 1: k=3/7/13 pattern convolutions + SimHash stem sketches -> state `(L, d_model)`.
fn encode_line_state(w: &Weights, cells: &[f32], num_lines: usize, cell_dim: usize) -> (Vec<f32>, usize) {
    let conv3 = conv1d_relu_sum(cells, num_lines, MAX_COLS, cell_dim, w.get("conv3_w"), w.get("conv3_b"));
    let conv7 = conv1d_relu_sum(cells, num_lines, MAX_COLS, cell_dim, w.get("conv7_w"), w.get("conv7_b"));
    let conv13 = conv1d_relu_sum(
        cells,
        num_lines,
        MAX_COLS,
        cell_dim,
        w.get("conv13_w"),
        w.get("conv13_b"),
    );

    let cell_sums = sum_columns(cells, num_lines, MAX_COLS, cell_dim);
    let col_sum_proj = w.get("col_sum_proj");
    let col_sums = matmul_add(
        &cell_sums,
        &col_sum_proj.data,
        None,
        num_lines,
        cell_dim,
        col_sum_proj.shape[1],
    );
    let (sketch_a, sketch_b, sketch_b_dim) = encode_sketches(w, cells, num_lines, cell_dim);

    let line_feats = concat_last(
        num_lines,
        &[
            (&col_sums, col_sum_proj.shape[1]),
            (&conv3, w.get("conv3_w").shape[2]),
            (&conv7, w.get("conv7_w").shape[2]),
            (&conv13, w.get("conv13_w").shape[2]),
        ],
    );
    let lmlp1_w = w.get("lmlp1_w");
    let mut line_hidden = matmul_add(
        &line_feats,
        &lmlp1_w.data,
        Some(&w.get("lmlp1_b").data),
        num_lines,
        lmlp1_w.shape[0],
        lmlp1_w.shape[1],
    );
    relu_in_place(&mut line_hidden);
    let lmlp2_w = w.get("lmlp2_w");
    let line_stats = matmul_add(
        &line_hidden,
        &lmlp2_w.data,
        Some(&w.get("lmlp2_b").data),
        num_lines,
        lmlp2_w.shape[0],
        lmlp2_w.shape[1],
    );

    let state = concat_last(
        num_lines,
        &[
            (&line_stats, lmlp2_w.shape[1]),
            (&sketch_a, SKETCH_DIM),
            (&sketch_b, sketch_b_dim),
        ],
    );
    (state, lmlp2_w.shape[1] + SKETCH_DIM + sketch_b_dim)
}

/// Block 2: one cross-line sink-attention + context-MLP residual pass.
fn apply_context_block(w: &Weights, layer: &str, state: &mut [f32], num_lines: usize, d_model: usize) {
    let delta = sink_attn(w, layer, state, num_lines, d_model);
    state.iter_mut().zip(&delta).for_each(|(s, &d)| *s += d);

    let c1_w = w.get(&format!("cmlp{layer}_w"));
    let c1_b = w.get(&format!("cmlp{layer}_b"));
    let mut ctx_hidden = matmul_add(state, &c1_w.data, Some(&c1_b.data), num_lines, d_model, c1_w.shape[1]);
    relu_in_place(&mut ctx_hidden);

    let c2_w = w.get(&format!("cmlp{layer}_2_w"));
    let c2_b = w.get(&format!("cmlp{layer}_2_b"));
    let ctx_out = matmul_add(
        &ctx_hidden,
        &c2_w.data,
        Some(&c2_b.data),
        num_lines,
        c2_w.shape[0],
        c2_w.shape[1],
    );
    state.iter_mut().zip(&ctx_out).for_each(|(s, &d)| *s += d);
}

fn forward_line_probs(w: &Weights, grid: &[u8], num_lines: usize) -> Vec<f32> {
    let (cells, cell_dim) = encode_cells(w, grid, num_lines);
    let (mut state, d_model) = encode_line_state(w, &cells, num_lines, cell_dim);
    for layer in ["1", "2"] {
        apply_context_block(w, layer, &mut state, num_lines, d_model);
    }
    let sq_w = w.get("sq_w");
    let mut probs = matmul_add(
        &state,
        &sq_w.data,
        Some(&w.get("sq_b").data),
        num_lines,
        d_model,
        sq_w.shape[1],
    );
    probs.iter_mut().for_each(|p| *p = sigmoid(*p));
    probs
}

/// Scores a single source file in pure Rust, returning the model's squiggles (threshold 0.55).
pub fn score_code(code: &str) -> Result<Vec<Squiggle>, String> {
    let w = weights()?;
    let (grid, num_lines) = encode_byte_grid(code);
    let probs = forward_line_probs(w, &grid, num_lines);
    let n_kinds = SPEC.len();
    let mut squiggles = Vec::new();
    for idx in 0..num_lines {
        let row = &probs[idx * n_kinds..(idx + 1) * n_kinds];
        let (best_kind, &best_prob) = row
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .unwrap_or((0, &0.0));
        if best_prob < THRESHOLD {
            continue;
        }
        let (kind, message) = SPEC[best_kind];
        squiggles.push(Squiggle {
            line: idx + 1,
            kind: kind.to_string(),
            message: message.to_string(),
        });
    }
    Ok(squiggles)
}

/// Half-window radius around changed lines: 2x `MAX_REL_DIST` (32) preserves the full cross-line
/// attention receptive field while avoiding scoring hundreds of unchanged lines in large files.
const WINDOW_RADIUS: usize = 64;
const WINDOW_THRESHOLD_LINES: usize = 256;

/// Scores only windows around `target_lines` (1-based) when `code` is large, mapping line numbers
/// back to the full file. Falls back to [`score_code`] on small files or when windows cover most
/// of the file.
pub fn score_code_windowed(code: &str, target_lines: &HashSet<usize>) -> Result<Vec<Squiggle>, String> {
    if target_lines.is_empty() {
        return Ok(Vec::new());
    }
    let lines: Vec<&str> = code.split('\n').collect();
    let total = lines.len();
    if total <= WINDOW_THRESHOLD_LINES {
        return score_code(code);
    }
    let mut intervals: Vec<(usize, usize)> = target_lines
        .iter()
        .filter(|&&line| line >= 1 && line <= total)
        .map(|&line| {
            let idx = line - 1;
            (idx.saturating_sub(WINDOW_RADIUS), (idx + WINDOW_RADIUS + 1).min(total))
        })
        .collect();
    if intervals.is_empty() {
        return Ok(Vec::new());
    }
    intervals.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    let covered: usize = merged.iter().map(|(s, e)| e - s).sum();
    if covered * 4 >= total * 3 {
        return score_code(code);
    }
    let mut out = Vec::new();
    for (start, end) in merged {
        let slice = lines[start..end].join("\n");
        for mut sq in score_code(&slice)? {
            sq.line += start;
            if target_lines.contains(&sq.line) {
                out.push(sq);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_rust_hygiene_model_loads_weights_and_flags_swallowed_error() {
        let code = "def load(p):\n    try:\n        return open(p).read()\n    except Exception:\n        pass\n";
        let squiggles = score_code(code).expect("weights load and score cleanly");
        assert!(
            squiggles.iter().any(|s| s.kind == "swallowed_error"),
            "expected swallowed_error squiggle, got: {squiggles:?}"
        );
    }

    #[test]
    fn windowed_scoring_maps_lines_back_on_large_files() {
        let mut lines: Vec<String> = (0..320).map(|i| format!("x_{i} = {i}")).collect();
        lines.push("def load(p):".into());
        lines.push("    try:".into());
        lines.push("        return open(p).read()".into());
        lines.push("    except Exception:".into());
        lines.push("        pass".into());
        let code = lines.join("\n");
        let target: HashSet<usize> = (321..=325).collect();
        let squiggles = score_code_windowed(&code, &target).expect("windowed score");
        assert!(
            squiggles
                .iter()
                .any(|s| s.kind == "swallowed_error" && (321..=325).contains(&s.line)),
            "expected windowed swallowed_error on lines 321..=325, got: {squiggles:?}"
        );
    }
}
