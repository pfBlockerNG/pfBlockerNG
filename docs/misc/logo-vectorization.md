# Logo vectorization — low-resolution raster to clean SVG

How [`docs/assets/logo.svg`](../assets/logo.svg) was produced from the only
available sources: small raster exports of the original pfBlockerNG mark
(a 366×366 JPEG and 375–460px PNGs; no vector original exists). Recorded so
the process is reproducible if a better source ever surfaces or another
asset needs the same treatment.

## Why naive tracing fails

The mark is flat-color art (4 colors: grey `#58585a`, red `#8b181a`,
dark-red shadow `#650818`, white), but the sources are not:

- **JPEG compression noise** — ringing around the lettering and 8px block
  edges. An auto-tracer follows every wiggle, producing lumpy outlines.
- **Anti-aliasing** — hundreds of intermediate colors along every edge,
  which a color tracer turns into stray in-between paths.
- **Low resolution** — at ~400px the small "BlockerNG" lettering is only
  ~30px tall; tracer smoothing at that scale distorts glyphs.

A direct `vtracer` run on the JPEG looked acceptable at 150px but visibly
bad at any larger render. The circular PNG traced better (flat colors, AA
only) but its lettering is worse than the JPEG's, so the JPEG had to be
made traceable instead.

## The pipeline

Dependencies: `pip3 install opencv-python-headless numpy vtracer cairosvg`
(cairosvg only for the verification renders).

1. **Denoise** the JPEG with OpenCV non-local means
   (`cv2.fastNlMeansDenoisingColored(im, None, 10, 10, 7, 21)`) — removes
   ringing/mosquito noise without eroding edges the way a median filter
   does (a median pass visibly ate the thin rule's end-caps).
2. **Upscale 5×** with Lanczos (`cv2.resize(..., fx=5, fy=5,
   interpolation=cv2.INTER_LANCZOS4)`). All later smoothing happens at
   this resolution, where a 1px correction is 0.2px of the original.
3. **Snap to the exact palette**: every pixel is assigned the nearest of
   the 4 true colors (squared RGB distance). This flattens the image to
   true flat art — AA gradients and residual noise all collapse onto the
   palette. Sample the palette from the image itself (`Image.getcolors`
   on a median-filtered copy; the 4 dominant clusters are unambiguous).
4. **Smooth JPEG block wobble** — the 8px block boundaries survive the
   snap as staircase wobble. For each palette color, blur the binary
   mask (`cv2.GaussianBlur(mask, (0,0), sigma)`) and take the per-pixel
   `argmax` across the blurred masks ("soft voting"). Sigma is scale- and
   content-dependent — sweep it and inspect a zoomed crop of the smallest
   lettering: at 5× (1830px canvas), σ=3 still left lumps, **σ=4.5 was
   right**, σ=6 began rounding corners, σ=9 melted glyphs into balloons.
5. **Trace each color as its own binary layer** (`vtracer`
   `colormode="binary"`, `mode="spline"`, `filter_speckle=15`,
   `corner_threshold=60`, `length_threshold=6.0`, `path_precision=1`),
   then recolor each layer's fill and stack them background-first
   (red → dark-red shadow → grey shield → white lettering). Tracing all
   colors in one `colormode="color"` pass let vtracer's color clustering
   corrupt a small glyph (the "e" of "BlockerNG" came out as a grey blob);
   per-color binary tracing is deterministic.
6. **Seal inter-layer gaps**: independently traced layers don't share
   boundaries, leaving hairline gaps where the background peeks through.
   Dilate every layer **except the white lettering** by a few pixels
   (`cv2.dilate`, 7×7 ellipse at 5× scale) so lower layers tuck under
   upper ones. Do not dilate the text layer — an all-layer dilation
   visibly fattened the small lettering.
7. **Clip to exact geometry**: auto-traced outer edges are never
   perfectly straight/round, and the eye catches that on a logo's
   silhouette. Wrap the traced art in a `<clipPath>` holding the exact
   shape (a `<rect rx=...>` here; a `<circle>` for the round variant),
   scale the art group up ~0.4% about its center so it overshoots, and
   put an exact background-color rect/circle underneath. The silhouette
   is then mathematically clean regardless of trace quality.

## Verify — render it back

After every parameter change, render the SVG back to PNG and inspect a
zoomed crop of the smallest text — judging the full logo at header size
hides exactly the defects that show up when the SVG is used anywhere
bigger:

```python
import cairosvg
from PIL import Image

cairosvg.svg2png(url="logo.svg", write_to="full.png", output_width=1830)
Image.open("full.png").crop((475, 1130, 1350, 1400)).save("crop.png")  # "BlockerNG" region
```

The defects this caught, in order: lumpy outlines (fixed by steps 1–4),
the corrupted "e" glyph (step 5), red hairlines under the white rule
(step 6), and fattened lettering from over-dilation (step 6's white-layer
exemption).
