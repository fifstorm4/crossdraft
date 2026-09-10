# はじめての方へ — 新しい暗号を解析するまで

Windows と Docker Desktop が入っている状態から、**自分で設計した暗号を解析する**
ところまでの手順です。

所要時間は、手順1〜4 が10分ほど。手順5以降は暗号次第です。

---

## 手順1 — 作業フォルダを作る

エクスプローラのアドレスバーに `powershell` と入力して Enter を押すと、
そのフォルダで PowerShell が開きます。あるいはスタートメニューから
「Windows PowerShell」を起動してください。

```powershell
cd C:\
mkdir crossdraft
cd crossdraft
```

**`C:\` の直下を勧めます。** 日本語やスペースを含むパスでも動きますが、
問題が起きたときの切り分けが増えます。

---

## 手順2 — CrossDraft を取ってくる

ブラウザで開きます。

```
https://github.com/fifstorm4/crossdraft
```

緑の **Code** ボタン → **Download ZIP**。

ダウンロードした `crossdraft-main.zip` を右クリック → **すべて展開**。
展開されたフォルダの**中身**を `C:\crossdraft` にコピーしてください。

`C:\crossdraft\run.ps1` が見える状態が正解です。

```powershell
cd C:\crossdraft
dir
```

Git をお使いなら、こちらの方が確実です。

```powershell
cd C:\
git clone https://github.com/fifstorm4/crossdraft.git
cd crossdraft
```

---

## 手順3 — Docker Desktop を起動する

タスクトレイのクジラのアイコンが動いていれば準備完了です。
止まっていればスタートメニューから起動して、1分ほど待ちます。

```powershell
docker version
```

`Server:` の行まで出れば大丈夫です。`error during connect` はまだ起動途中です。

---

## 手順4 — 動くことを確かめる

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
$env:IMAGE = "ghcr.io/fifstorm4/crossdraft:0.1.0"
.\run.ps1 selftest
```

1行目は `run.ps1` の実行許可です。**この PowerShell を閉じると元に戻ります**ので、
システム設定は変わりません。ウィンドウを開き直すたびに必要です。

初回はイメージを取得します。**2分ほど**。

```
pulling ghcr.io/fifstorm4/crossdraft:0.1.0
...
  PASS  cross-validation against Digital  [21s]
  PASS  PRESENT against CLAASP's own model  [3s]
  PASS  randomised circuits  [39s]
  PASS  the GUI serves and its stages run  [5s]

  4/4 suites passed in 68s
  This installation reproduces the reference results.
```

**この4行が、あなたの PC で参照結果が再現されたという証拠です。**
Digital のシミュレータと CLAASP 内蔵の PRESENT に照らして確認しているので、
作者の環境の話ではありません。

`building ... allow 20-40 min` と出た場合は取得に失敗してローカルビルドに
落ちています。それでも動きますが、時間がかかります。

---

## 手順5 — 既存の暗号で一周する

自分の暗号に入る前に、動きを確かめます。

```powershell
.\run.ps1 list
```

6つの暗号が出ます。PRESENT で試します。

```powershell
.\run.ps1 build   present
.\run.ps1 verify  present
.\run.ps1 analyse present --rounds 3 --show
```

```
  published vectors: 4/4
  circuit vs reference at 31 rounds: 8/8

  best differential characteristic over 3 rounds: weight 8.0
  active S-boxes at most: 4
```

**上が論文との一致、下が回路と参照実装の一致です。** 活性S ボックス4個は
CHES 2007 の公表値と同じ。

### 回路を見る

`C:\crossdraft\build\present\present_round.dig` ができています。
Digital で開くと、S ボックス16個と pLayer の64本配線が見えます。
**これが CLAASP に渡っているものそのものです。**

Digital をお持ちでなければ [こちら](https://github.com/hneemann/Digital/releases/latest)
から `Digital.zip` を取って展開し、`Digital.jar` をダブルクリックしてください。

---

## 手順6 — 自分の暗号を書く

**`C:\crossdraft\mycipher.py` を作ります。** このファイル名は決まっていて、
作業フォルダに置くと自動で読み込まれます。ツール本体には触りません。

メモ帳でも構いません。まずは動く最小のものから。

```python
"""My cipher."""

SBOX = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]

# 出力ビット j は入力ビット MAP[j] を取る
MAP = [(4 * i) % 63 for i in range(63)] + [63]


def my_round(b):
    state = b.inp("state", 64)
    rk    = b.inp("rk", 64)

    x = b.xor(state, rk)
    x = b.sbox_layer(x, SBOX)
    x = b.permute(x, MAP)

    b.out("state'", x)


def my_reference(plaintext, key, rounds=20):
    s = plaintext
    k = key & ((1 << 64) - 1)
    for _ in range(rounds):
        s ^= k
        s = sum(SBOX[(s >> (4 * i)) & 0xF] << (4 * i) for i in range(16))
        s = sum(((s >> MAP[j]) & 1) << j for j in range(64))
    return s


MYCIPHER = {
    "name": "mycipher",
    "parts": {"round": my_round},
    "reference": my_reference,
    "state": ["state"],
    "block_bits": 64,
    "key_bits": 64,
    "rounds": 20,
    "bit_order": "lsb",
    "vectors": [],
    "params": lambda i, key: {"rk": key & ((1 << 64) - 1)},
}
```

**要点は2つだけです。**

`In "state"` と `Out "state'"` が対になっていること。これがループの宣言で、
ラウンド数は解析時の引数になります。**20ラウンド描く必要はありません。**

回路と参照実装を**別々に書く**こと。同じコードを共有すると、両方が同じ誤りを
持ったときに気づけません。

保存したら確認します。

```powershell
.\run.ps1 list
```

`mycipher` が一覧に出れば読み込まれています。

---

## 手順7 — 自分の暗号を解析する

**解析系のコマンドは `verify` を通っていない回路を受け付けません。**

```
  mycipher has not passed `verify`.

    python3 digcli.py verify mycipher
```

理由は、誤って翻訳された回路からも**もっともらしい差分特性が出てくる**からです。
出てきた数値のどこにも異常はなく、それを排除できる唯一の機会が `verify` です。

覚えておくことは3つ。

| | |
|---|---|
| 回路や `mycipher.py` を変更したら | **`verify` をやり直す** |
| 参照実装をまだ書いていない設計を見たいとき | **`--unverified`** を付ける |
| 変更していないのに拒否されたら | 何が変わったかをメッセージが名指しします |

`--unverified` を付けた場合、出てくる結果は**その回路の性質**であって、
意図した暗号の性質ではありません。ツールもそう言います。

```powershell
.\run.ps1 build   mycipher
.\run.ps1 verify  mycipher
.\run.ps1 analyse mycipher --rounds 3 --show
```

```
  circuit vs reference at 20 rounds: 8/8

  R   weight  active  state
  0      2.0       1  ...
  1      4.0       2  ...
  2      8.0       4  ...

  active S-boxes: 7
```

**これで新しい暗号の差分解析ができました。**

続けて調べられること。

```powershell
.\run.ps1 sbox       mycipher --show          # DDT と LAT
.\run.ps1 bound      mycipher --rounds 3 --weights 6 7 8
.\run.ps1 cluster    mycipher --rounds 3      # 特性から差分へ
.\run.ps1 impossible mycipher --rounds 3      # 不能差分
.\run.ps1 relatedkey mycipher --sweep 1,4     # 関連鍵
.\run.ps1 random     mycipher --rounds 20     # アバランシェと拡散
.\run.ps1 cost       mycipher --rounds 20     # ゲート見積もり
```

### 論文用の出力

```powershell
.\run.ps1 analyse mycipher --rounds 3 --export fig.pdf --export table.tex
.\run.ps1 env     mycipher --latex > methodology.tex
```

`env` はバージョンに加えて**回路の SHA-256** を出します。同じ CLAASP・同じ
ソルバでも回路が1本の配線で違えば結果は変わるので、ダイジェストが
「同じものを解析した」という主張を検証可能にします。

---

## 手順8 — 画面で操作する

```powershell
.\run.ps1 gui
```

ブラウザで `http://127.0.0.1:8765`。ラウンド数を変えて何度も試す、
トレイルを表で読む、といった用途はこちらが楽です。

**Replicate タブ**では、論文に載っているトレイルを CSV に写して、
自分のモデルで再現できるか確かめられます。

止めるときは PowerShell で **Ctrl+C**。

---

## 詰まったとき

```powershell
.\run.ps1 doctor
```

必要なものが揃っているかを1つずつ確認し、足りなければ対処法まで出します。

| 症状 | 対処 |
|---|---|
| `run.ps1 は実行できません` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `.\run.ps1 が認識されません` | `cd C:\crossdraft` を忘れている |
| `error during connect` | Docker Desktop がまだ起動していない |
| `mycipher` が一覧に出ない | ファイル名か置き場所。`C:\crossdraft\mycipher.py` |
| `no state variable found` | `In "x"` と `Out "x'"` の対がない |
| `has not passed verify` | `verify` を先に実行する。手順7を参照 |
| `definition has changed since verify` | `mycipher.py` を変更した。`verify` をやり直す |
| `circuit vs reference: 0/N` | 回路と参照実装が食い違う。**回路を疑う** |
| `published vectors: 0/N` | **参照実装を疑う**。回路ではない |
| `port is already allocated` | 前回の GUI が残っている。`docker ps` で確認して `docker stop` |

最後から2つ目と3つ目は意味が違います。**論文との照合が落ちたら参照実装、
回路との照合が落ちたら回路。** 切り分けができるのがこの構造の利点です。

---

## 次に読むもの

| | |
|---|---|
| `ADD_A_CIPHER_ja.md` | 暗号の書き方。部品の一覧、どこまで回路に描くか、6つのお手本の使い分け |
| `README.md` | 全体像と、各コマンドが何を保証しているか |
| `python/ciphers.py` | 6つの実装。作りたいものに近いものをコピーするのが早い |

お手本は、それぞれ違う要素を含むように選んであります。

| 暗号 | 構造 | 参考になる点 |
|---|---|---|
| PRESENT-80 | SPN | ビット置換、64ビットを超える鍵レジスタ |
| GIFT-64-128 | SPN | ニブルの一部にしか届かないラウンド鍵 |
| LLBC-128-128 | Feistel | 回転、鍵スケジュールも回路として描く |
| Speck32/64 | ARX | 法 2ⁿ 加算 |
| Simon32/64 | AND-RX | ビット単位 AND |
| SKINNY-64-128 | SPN | MixColumns、tweakey |

軽量暗号のほとんどは、非線形演算（S ボックス・加算・AND）と線形演算
（回転・置換・MixColumns）の組み合わせです。**6つの中に全部あります。**
