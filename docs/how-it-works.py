# Generates how-it-works.svg next to this file: python3 docs/how-it-works.py
import html
W, H = 1160, 1300
out = []
def e(s): out.append(s)
def text(x, y, lines, size=15, weight=400, fill='#1f2933', anchor='middle', mono=False):
    fam = "ui-monospace,SFMono-Regular,Menlo,monospace" if mono else "system-ui,-apple-system,'Segoe UI',Roboto,sans-serif"
    for i, l in enumerate(lines):
        e(f'<text x="{x}" y="{y + i*size*1.35:.0f}" font-family="{fam}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{html.escape(l)}</text>')
def box(x, y, w, h, lines, fill='#fff', stroke='#cbd2d9', size=15, weight=400, color='#1f2933', mono=False, dash=False):
    d = ' stroke-dasharray="6 5"' if dash else ''
    e(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{fill}" stroke="{stroke}" stroke-width="1.5"{d}/>')
    n = len(lines); lh = size*1.35
    text(x + w/2, y + h/2 - (n-1)*lh/2 + size*0.35, lines, size, weight, color, mono=mono)
def arrow(x1, y1, x2, y2, label=None, color='#52606d', above=True, lsize=13, dash=False):
    d = ' stroke-dasharray="6 5"' if dash else ''
    e(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="2"{d} marker-end="url(#a{color[1:]})"/>')
    if label:
        lines = label if isinstance(label, list) else [label]
        mx = (x1+x2)/2; my = (y1+y2)/2
        if y1 == y2:
            base = my - 8 - (len(lines)-1)*lsize*1.35 if above else my + 18
            text(mx, base, lines, lsize, 500, color)
        else:
            text(mx + 10, my + 4, lines, lsize, 500, color, anchor='start')
colors = ['#52606d', '#0e7c86', '#b44d12', '#6b46c1', '#2f855a']
e(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">')
e('<defs>' + ''.join(f'<marker id="a{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>' for c in colors) + '</defs>')
e(f'<rect width="{W}" height="{H}" fill="#f7f8fa"/>')
text(W/2, 46, ['How Chaumian sessions work'], 28, 700)
text(W/2, 76, ['The server is paid for every chat, but cannot tell which account a chat came from, or which chats go together.'], 15, 400, '#52606d')

# Columns
DX, DW = 40, 440      # device column
SX, SW = 680, 440     # server column
e(f'<rect x="{DX-10}" y="100" width="{DW+20}" height="950" rx="16" fill="#e6f6f7"/>')
e(f'<rect x="{SX-10}" y="100" width="{SW+20}" height="950" rx="16" fill="#eceff3"/>')
text(DX + DW/2, 130, ['Your device (browser, phone, agent)'], 17, 700, '#0e7c86')
text(SX + SW/2, 130, ['The server'], 17, 700, '#3e4c59')

def step(y, n, title):
    e(f'<circle cx="{W/2}" cy="{y}" r="15" fill="#1f2933"/>')
    text(W/2, y + 5, [str(n)], 15, 700, '#fff')
    text(W/2, y + 38, [title], 15, 700, '#1f2933')

# 0. Keys
y = 160
box(DX, y, DW, 52, ['Account number  4417 2093 8865 0112'], '#fff', '#0e7c86', 16, 600, mono=False)
arrow(DX + DW/2, y + 52, DX + DW/2, y + 92, ['Argon2id: a deliberately slow hash'], '#0e7c86')
box(DX, y + 96, 200, 58, ['Seed', 'never leaves the device'], '#0e7c86', '#0e7c86', 14, 600, '#fff')
box(DX + 240, y + 96, 200, 58, ['Login key', 'sent to sign in'], '#fff', '#0e7c86', 14)
box(SX, y + 96, SW, 58, ['Account: stores only a keyed hash of the login key', 'Never sees the number or the seed'], '#fff', '#9aa5b1', 14)
arrow(DX + DW, y + 125, SX, y + 125, 'sign in', '#52606d')

# 1. Top up
y = 360
step(y, 1, 'Top up the wallet')
box(DX, y + 72, DW, 58, ['Makes blank vouchers from the seed', 'and blinds them (scrambles them)'], '#fff', '#cbd2d9', 14)
arrow(DX + DW, y + 87, SX, y + 87, ['blinded blanks + account key'], '#b44d12')
box(SX, y + 72, SW, 58, ['Takes $1 from the account and signs the blanks', 'without seeing them (blind signature)'], '#fff', '#cbd2d9', 14)
arrow(SX, y + 120, DX + DW, y + 120, None, '#b44d12')
text(W/2, y + 140, ['signatures'], 13, 500, '#b44d12')
box(DX, y + 152, DW, 46, ['Unblinds them: a wallet of vouchers the server has never seen'], '#fff7ed', '#b44d12', 14, 600, '#7b341e')

# 2. Open
y = 600
step(y, 2, 'Each conversation opens a session')
box(DX, y + 72, DW, 58, ['Pays with vouchers and picks a session secret', 'sk-chs1_…  (also from the seed)'], '#fff', '#cbd2d9', 14)
arrow(DX + DW, y + 101, SX, y + 101, ['vouchers + hash of the secret', 'no account, no cookie'], '#6b46c1')
box(SX, y + 72, SW, 58, ['Vouchers valid and never spent: session open', 'It cannot tell whose vouchers they are'], '#fff', '#cbd2d9', 14)

# 3. Chat
y = 760
step(y, 3, 'Chat')
box(DX, y + 72, DW, 46, ['Every request: Authorization: Bearer sk-chs1_…'], '#fff', '#cbd2d9', 14)
arrow(DX + DW, y + 95, SX, y + 95, ['the secret instead of an API key'], '#6b46c1')
box(SX, y + 72, SW, 46, ['Charges each request to the session, per token'], '#fff', '#cbd2d9', 14)

# 4. Close
y = 900
step(y, 4, 'Quiet for 5 minutes: close')
box(DX, y + 72, DW, 58, ['Sends blank vouchers for the change', 'Gets them back signed: into the wallet'], '#fff', '#cbd2d9', 14)
arrow(DX + DW, y + 90, SX, y + 90, None, '#b44d12')
arrow(SX, y + 116, DX + DW, y + 116, None, '#b44d12')
text(W/2, y + 140, ['change, blind-signed'], 13, 500, '#b44d12')
box(SX, y + 72, SW, 58, ['Signs the change blindly', 'and forgets the session once collected'], '#fff', '#cbd2d9', 14)

# What the server can see
y = 1090
e(f'<rect x="30" y="{y}" width="{W-60}" height="190" rx="16" fill="#fff" stroke="#cbd2d9" stroke-width="1.5"/>')
text(60, y + 34, ['All the server can see'], 17, 700, '#1f2933', anchor='start')
box(60, y + 54, 440, 58, ['Account 4f1c…  took $1.00 at 10:02', 'Account 4f1c…  took $1.00 at 16:40'], '#fff7ed', '#b44d12', 14, 400, '#7b341e', mono=True)
box(660, y + 54, 440, 58, ['Session 7a9e…  $0.50, 41 requests, closed', 'Session c03b…  $0.50, 12 requests, closed'], '#f3f0ff', '#6b46c1', 14, 400, '#44337a', mono=True)
e(f'<line x1="510" y1="{y+83}" x2="650" y2="{y+83}" stroke="#c53030" stroke-width="2.5" stroke-dasharray="7 6"/>')
e(f'<line x1="566" y1="{y+70}" x2="594" y2="{y+96}" stroke="#c53030" stroke-width="3"/><line x1="594" y1="{y+70}" x2="566" y2="{y+96}" stroke="#c53030" stroke-width="3"/>')
text(W/2, y + 140, ['No record joins an account to a session, or one session to another.'], 15, 600, '#c53030')
text(W/2, y + 166, ['Lost the device or closed Tor Browser? Type the number again: the same seed rebuilds every secret and voucher, and the money comes back.'], 13.5, 400, '#52606d')
e('</svg>')
open(__file__.replace('.py', '.svg'), 'w').write('\n'.join(out))
