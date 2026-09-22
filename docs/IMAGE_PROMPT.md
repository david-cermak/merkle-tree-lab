# Image Generation Prompt for Merkle Certificate Schematic

Use this prompt with DALL·E, Midjourney, Stable Diffusion, or similar to generate a front-page schematic.

---

## Primary Prompt (concise)

```
Technical schematic diagram, infographic style, dark background. Two columns side by side:

LEFT COLUMN "Traditional PKI": A vertical chain of 3 linked boxes. Top box labeled "Certificate" (green), middle "Intermediate CA" (amber), bottom "Root CA" (amber). Arrows connecting them downward. Caption: "Chain of trust".

RIGHT COLUMN "Merkle / CT-style": Three distinct boxes stacked: (1) "Certificate" in green, (2) "Merkle Proof" in blue with small tree/branch icon, (3) "Signed Tree Root" in purple. No chain between them. Caption: "No chain. Three pieces."

Below: A horizontal flow: "Submit cert" → "Log sequences" → "Fetch proof" → "Verify". Clean, minimal, tech aesthetic. No photorealism.
```

---

## Extended Prompt (more control)

```
Create a professional technical infographic for a cybersecurity / cryptography demo. Dark theme (#0f0f12 background). Clean vector-style illustration.

LAYOUT: Split into two comparison sections.

SECTION A - "Traditional PKI" (left):
- Three rectangular blocks stacked vertically, connected by chain links or arrows
- Block 1: "Certificate" (leaf green #22c55e)
- Block 2: "Intermediate CA" (amber #f59e0b)
- Block 3: "Root CA" (amber)
- Visual: chain of trust, multiple certificates needed

SECTION B - "Merkle Certificate" (right):
- Three separate blocks, NOT chained:
- Block 1: "Certificate" (green) - the leaf
- Block 2: "Merkle Proof" (blue #3b82f6) - show small Merkle tree branches or hash nodes
- Block 3: "Signed Tree Root" (purple #a855f7) - checkmark or seal icon
- Caption: "What we send instead of a chain"

BOTTOM: Horizontal flowchart with 4 steps:
1. Submit cert to log
2. Log sequences into tree
3. Fetch proof + signed root
4. Verify: hash(cert) + proof → root

Style: Flat design, sharp edges, tech/dashboard aesthetic. Sans-serif labels. No people, no 3D renders. Suitable for documentation or presentation slide.
```

---

## Alternative: Abstract / Metaphor

```
Infographic: "Certificate without the chain". 

Left: A literal chain with 3 links (cert, intermediate, root) - heavy, many pieces.
Right: A single certificate leaf with a small Merkle tree growing beside it, and a glowing root hash at the top. Three clean blocks: Cert | Proof | Root.

Style: Isometric or flat 2D. Dark blue/gray background. Accent colors: green (cert), blue (proof), purple (root). Minimal, educational, memorable.
```

---

## Key Visual Elements to Include

| Element | Color | Meaning |
|---------|-------|---------|
| Certificate | Green | The actual cert (leaf in the tree) |
| Merkle proof | Blue | Audit path / sibling hashes |
| Signed tree root | Purple | Log's commitment (size + root hash) |
| Traditional chain | Amber | Old approach: multiple CA certs |

---

## What to Emphasize

1. **Three pieces, not a chain**: Cert + proof + root
2. **No CA intermediates**: The log replaces chain-of-trust
3. **Verification flow**: hash(cert) → combine with proof → match root
4. **Certificate Transparency**: Real-world use case
