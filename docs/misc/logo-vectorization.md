# Logo vectorization — low-resolution raster to clean SVG

How [`docs/assets/logo.svg`](../assets/logo.svg) made from only sources on hand: small raster exports of original pfBlockerNG mark (366×366 JPEG, 375–460px PNGs; no vector original). Recorded so process reproducible if better source shows up or another asset need same treatment.

## Why naive tracing fails

Mark is flat-color art (4 colors: grey `#58585a`, red `#8b181a`, dark-red shadow `#650818`, white). Sources not:

- **JPEG compression noise** — ringing around lettering and 8px block edges. Auto-tracer follow every wiggle, make lumpy outlines.
- **Anti-aliasing** — hundreds of in-between colors along every edge. Color tracer turn them into stray in-between paths.
- **Low resolution** — at ~400px small "BlockerNG" lettering only ~30px tall. Tracer smoothing at that scale distort glyphs.

Direct `vtracer` run on JPEG looked OK at 150px, visibly bad any larger render. Circular PNG traced better (flat colors, AA only) but its lettering worse than JPEG's. So JPEG had to be made traceable instead.

## The pipeline

Dependencies: `pip3 install opencv-python-headless numpy vtracer cairosvg` (cairosvg only for verification renders).

1. **Denoise** JPEG with OpenCV non-local means
   (`cv2.fastNlMeansDenoisingColored(im, None, 10, 10, 7, 21)`) — kill
   ringing/mosquito noise without eroding edges like median filter do
   (median pass visibly ate thin rule's end-caps).
2. **Upscale 5×** with Lanczos (`cv2.resize(..., fx=5, fy=5,
   interpolation=cv2.INTER_LANCZOS4)`). All later smoothing happen at
   this resolution, where 1px correction is 0.2px of original.
3. **Snap to the exact palette**: every pixel assigned nearest of 4 true
   colors (squared RGB distance). Flattens image to true flat art — AA
   gradients and leftover noise all collapse onto palette. Sample palette
   from image itself (`Image.getcolors` on median-filtered copy; 4
   dominant clusters unambiguous).
4. **Smooth JPEG block wobble** — 8px block boundaries survive snap as
   staircase wobble. Per palette color, blur binary mask
   (`cv2.GaussianBlur(mask, (0,0), sigma)`), take per-pixel `argmax`
   across blurred masks ("soft voting"). Sigma is scale- and
   content-dependent — sweep it, inspect zoomed crop of smallest
   lettering: at 5× (1830px canvas), σ=3 still left lumps, **σ=4.5 was
   right**, σ=6 began rounding corners, σ=9 melted glyphs into balloons.
5. **Trace each color as its own binary layer** (`vtracer`
   `colormode="binary"`, `mode="spline"`, `filter_speckle=15`,
   `corner_threshold=60`, `length_threshold=6.0`, `path_precision=1`),
   then recolor each layer's fill and stack background-first
   (red → dark-red shadow → grey shield → white lettering). Tracing all
   colors in one `colormode="color"` pass let vtracer's color clustering
   corrupt a small glyph ("e" of "BlockerNG" came out grey blob);
   per-color binary tracing is deterministic.
6. **Seal inter-layer gaps**: independently traced layers don't share
   boundaries, leaving hairline gaps where background peeks through.
   Dilate every layer **except white lettering** by few pixels
   (`cv2.dilate`, 7×7 ellipse at 5× scale) so lower layers tuck under
   upper ones. Do not dilate text layer — all-layer dilation visibly
   fattened small lettering.
7. **Clip to exact geometry**: auto-traced outer edges never perfectly
   straight/round, and eye catch that on logo silhouette. Wrap traced art
   in `<clipPath>` holding exact shape (`<rect rx=...>` here; `<circle>`
   for round variant), scale art group up ~0.4% about its center so it
   overshoots, put exact background-color rect/circle underneath.
   Silhouette then mathematically clean regardless of trace quality.

## Verify — render it back

After every parameter change, render SVG back to PNG and inspect zoomed crop of smallest text — judging full logo at header size hides exactly the defects that show up when SVG used anywhere bigger:

```python
import cairosvg
from PIL import Image

cairosvg.svg2png(url="logo.svg", write_to="full.png", output_width=1830)
Image.open("full.png").crop((475, 1130, 1350, 1400)).save("crop.png")  # "BlockerNG" region
```

Defects this caught, in order: lumpy outlines (fixed by steps 1–4), corrupted "e" glyph (step 5), red hairlines under white rule (step 6), fattened lettering from over-dilation (step 6's white-layer exemption).
