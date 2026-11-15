# Generates how-it-works.svg next to this file: python3 docs/how-it-works.py
import html
W, H = 1600, 940
SANS = "Inter,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif"
MONO = "'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace"
INK, MUTED, LINE = '#0f172a', '#64748b', '#e2e8f0'
MONEY, SESSION, RED = '#4f46e5', '#0d9488', '#dc2626'
out = []
def e(s): out.append(s)
def t(x, y, s, size=16, weight=400, fill=INK, anchor='start', mono=False, spacing=0):
    ls = f' letter-spacing="{spacing}"' if spacing else ''
    e(f'<text x="{x}" y="{y}" font-family="{MONO if mono else SANS}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{ls}>{html.escape(s)}</text>')
def rect(x, y, w, h, fill='#fff', stroke=LINE, rx=14, extra=''):
    e(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="1.5"{extra}/>')
def arrow(x1, x2, y, color, label, label_y, mono=True):
    e(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{color}" stroke-width="2.5" marker-end="url(#m{color[1:]})"/>')
    t((x1 + x2) / 2, label_y, label, 15, 500, color, 'middle', mono)

e(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">')
e('<defs>' + ''.join(
    f'<marker id="m{c[1:]}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
    for c in (MONEY, SESSION, MUTED)) +
    '<filter id="sh" x="-5%" y="-10%" width="110%" height="130%"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#0f172a" flood-opacity="0.06"/></filter></defs>')
e(f'<rect width="{W}" height="{H}" fill="#f8fafc"/>')

# Header
t(80, 78, 'How unlinkable inference works', 40, 700)
t(80, 116, 'The service is paid for every chat but can’t tell whose chat it is, or which chats belong together.', 20, 400, MUTED)

# Lanes
DX, SX, CW = 80, 1020, 500          # device and service card columns
AX1, AX2 = DX + CW + 14, SX - 14    # arrow span
LY, LH = 156, 510
for x, label in ((DX, 'YOUR DEVICE'), (SX, 'THE SERVICE')):
    rect(x - 16, LY, CW + 32, LH, '#f1f5f9', '#f1f5f9', 20)
    t(x + CW / 2, LY + 34, label, 14, 700, MUTED, 'middle', spacing=2)

ROW0, STEP, CH = LY + 58, 110, 88
rows = [
    # (device title, device line, service title, service line, arrows)
    ('Get vouchers', 'Makes fresh vouchers and blinds them',
     'Signs them blind', 'Debits $1. Never sees the vouchers.',
     [('→', MONEY, 'blinded vouchers · account'), ('←', MONEY, 'blind signatures')]),
    ('Open a chat', 'Pays with vouchers, no account',
     'Opens a session', 'Checks the signatures. Can’t tell whose.',
     [('→', SESSION, 'vouchers · session key hash')]),
    ('Chat', 'Bearer sk-unl1_…',
     'Bills the session', 'Per token, to a fraction of a cent',
     [('→', SESSION, 'prompts · session key')]),
    ('Close when idle', 'After 5 quiet minutes',
     'Returns the change', 'As new vouchers it has never seen',
     [('→', MONEY, 'blank vouchers'), ('←', MONEY, 'change, signed blind')]),
]
for i, (dt, dl, st, sl, arrows) in enumerate(rows):
    y = ROW0 + i * STEP
    rect(DX, y, CW, CH, extra=' filter="url(#sh)"')
    e(f'<circle cx="{DX + 44}" cy="{y + CH / 2}" r="19" fill="{INK}"/>')
    t(DX + 44, y + CH / 2 + 6, str(i + 1), 17, 700, '#fff', 'middle')
    t(DX + 80, y + 38, dt, 21, 650)
    t(DX + 80, y + 64, dl, 16, 400, MUTED, mono=dl.startswith('Bearer'))
    rect(SX, y, CW, CH, extra=' filter="url(#sh)"')
    t(SX + 32, y + 38, st, 21, 650)
    t(SX + 32, y + 64, sl, 16, 400, MUTED)
    if len(arrows) == 1:
        d, c, label = arrows[0]
        arrow(AX1, AX2, y + 54, c, label, y + 40)
    else:
        (_, c1, l1), (_, c2, l2) = arrows
        arrow(AX1, AX2, y + 30, c1, l1, y + 19)
        arrow(AX2, AX1, y + 62, c2, l2, y + 86)

# What the service sees
PY = LY + LH + 30
rect(64, PY, W - 128, 200, '#fff', LINE, 20, ' filter="url(#sh)"')
t(104, PY + 46, 'All the service sees', 22, 700)
t(W - 104, PY + 46, 'Two ledgers with nothing to join them', 17, 500, RED, 'end')
LW = 560
for x, head, color, lines in (
        (104, 'ACCOUNTS', MONEY, [('4f1c…', '−$1.00', '10:02'), ('4f1c…', '−$1.00', '16:40')]),
        (W - 104 - LW, 'SESSIONS', SESSION, [('7a9e…', '$0.50', '41 requests'), ('c03b…', '$0.50', '12 requests')])):
    rect(x, PY + 70, LW, 104, '#f8fafc', LINE, 12)
    e(f'<rect x="{x}" y="{PY + 70}" width="5" height="104" rx="2" fill="{color}"/>')
    t(x + 28, PY + 98, head, 13, 700, color, spacing=2)
    for j, cols in enumerate(lines):
        for k, col in enumerate(cols):
            t(x + 28 + k * 130, PY + 128 + j * 28, col, 17, 500, INK, mono=True)
cx, cy = W / 2, PY + 122
e(f'<line x1="{104 + LW + 20}" y1="{cy}" x2="{cx - 30}" y2="{cy}" stroke="{RED}" stroke-width="2" stroke-dasharray="6 6"/>')
e(f'<line x1="{cx + 30}" y1="{cy}" x2="{W - 104 - LW - 20}" y2="{cy}" stroke="{RED}" stroke-width="2" stroke-dasharray="6 6"/>')
e(f'<circle cx="{cx}" cy="{cy}" r="22" fill="#fef2f2" stroke="{RED}" stroke-width="2"/>')
e(f'<path d="M{cx-8},{cy-8} L{cx+8},{cy+8} M{cx+8},{cy-8} L{cx-8},{cy+8}" stroke="{RED}" stroke-width="3" stroke-linecap="round"/>')

# Footer
t(W / 2, H - 22, 'Blind RSA signatures (RFC 9474). Every voucher and key derives from the account number, so the wallet restores on any device.', 15, 400, MUTED, 'middle')
e('</svg>')
open(__file__.replace('.py', '.svg'), 'w').write('\n'.join(out))
