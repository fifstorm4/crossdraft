# 自分の暗号を追加する

CrossDraft に暗号を追加する作業は、**辞書を1つ書くだけ**です。既存の6つはすべて
その形で書かれていて、新しいものも同じ形になります。

置き場所は2つあります。

| 置き場所 | 用途 |
|---|---|
| **作業フォルダの `mycipher.py`** | **自分の暗号。これを勧めます** |
| `python/ciphers.py` | ツールに同梱する暗号 |

前者を勧めるのは、公開イメージを使う場合に `python/ciphers.py` を編集しても
**コンテナからは見えない**からです。コンテナはイメージ内のコードを実行します。
作業フォルダの `mycipher.py` は自動で読み込まれるので、イメージを作り直す必要が
ありません。自分の設計が結果の隣に残るという利点もあります。

ファイル名は `CROSSDRAFT_CIPHERS` 環境変数で変えられます。

所要時間は、仕様が手元にあれば30分から1時間程度。ここでは PRESENT を例に、
何をどこに書くかを順に説明します。

---

## 全体像

暗号を1つ追加すると、**3つの記述が揃うこと**が求められます。

```
公開テストベクタ  →  参照実装  →  回路
      論文             Python        Digital
```

順序に意味があります。**公開ベクタが参照実装を固定し、参照実装が回路を固定します。**
どれか1つでは足りません。参照実装だけなら「自分が書いた通りに動く」ことしか言えず、
回路だけなら「Digital と評価器が同じ読み方をしている」ことしか言えない。3つ揃って
初めて「この回路はその暗号である」と言えます。

`verify` はこの3層を一度に確認します。

---

## 手順1 — ラウンド関数を描く

`python/ciphers.py` に関数を1つ書きます。座標も配線も書きません。

```python
def present_round(b):
    state = b.inp("state", 64)
    rk    = b.inp("rk", 64)

    x = b.xor(state, rk)
    x = b.sbox_layer(x, PRESENT_SBOX)
    x = b.permute(x, PRESENT_PMAP)

    b.out("state'", x)
```

これで全部です。レイアウト、スプリッタ、S ボックスの select ピンに要る定数、
配線はすべて `Builder` が処理します。

### ループの宣言

**`In "state"` と `Out "state'"` が対になっているのが要点です。**

| 書き方 | 意味 |
|---|---|
| `In "X"` と `Out "X'"` が対 | **状態変数**。次ラウンドへ送られる |
| `In "rk"` に対応する `Out` がない | **毎ラウンドの引数**。呼び出し側が供給 |

`X_next` も `X'` の代わりに使えます。

**ラウンドは1つだけ描きます。** 20ラウンド描くのは20回ミスをする機会を作るだけで、
Digital も1ラウンドしかシミュレートできません。ラウンド数は解析時の引数です。

### 使える部品

| 部品 | 何を出すか |
|---|---|
| `xor(a, b, …)` | バス全幅の XOR |
| `gate("And", a, b)` `not_(x)` | AND / OR / NAND / NOR / NOT |
| `modadd(a, b)` | 法 2ⁿ 加算（ARX の A） |
| `rotl(x, n)` `rotr(x, n)` | 巡回シフト |
| `sbox_layer(x, table)` | 語の全セルに同じ表を適用 |
| `permute(x, mapping)` | ビット置換。`out j <- in mapping[j]` |
| `mix_columns(cells, matrix, cell_bits, poly)` | GF(2ᵐ) 行列。XOR に展開される |
| `words(x, 16)` `join([…])` | 語への分割と結合 |
| `wide_in(name, 80)` `wide_rotl(w, 61)` | 64ビットを超えるレジスタ |
| `const(value, bits)` | 定数 |

### どこまで回路に描くか

**計算は描き、並べ替えは描かない**、が目安です。

SKINNY の tweakey スケジュールはセルの置換と 4 ビット LFSR で、
描けば16本の配線と論理ゼロになります。呼び出し側で計算して `rtk` として渡す方が、
回路が仕様の演算だけを映すので読みやすい。

一方 LLBC の鍵スケジュールは回転と XOR の計算なので描いています。

**厳密な線引きはありません。** 結果が同じなら、再現性と整合性チェックが楽な方を
選んでください。

---

## 手順2 — 参照実装を書く

素の Python で、仕様書の通りに書きます。回路のことは忘れて構いません。

```python
def present_reference(plaintext, key, rounds=31):
    keys = _present_round_keys(key, rounds)
    s = plaintext
    for r in range(rounds):
        s ^= keys[r]
        s = sum(PRESENT_SBOX[(s >> (4*i)) & 0xF] << (4*i) for i in range(16))
        t = 0
        for i in range(64):
            if (s >> i) & 1:
                t |= 1 << PRESENT_P[i]
        s = t
    return s ^ keys[rounds]
```

**回路と参照実装は別々に書いてください。** 同じコードを共有すると、両方が同じ誤りを
持ったときに気づけません。別々に書いて一致することが証拠になります。

---

## 手順3 — 辞書を書く

```python
PRESENT = {
    "name": "present",
    "parts": {"round": present_round},
    "reference": present_reference,
    "state": ["state"],
    "block_bits": 64,
    "key_bits": 80,
    "rounds": 31,
    "bit_order": "lsb",
    "vectors": [
        (0x0000000000000000, 0x00000000000000000000, 0x5579C1387B228445),
    ],
    "params": lambda i, key: {"rk": _present_round_keys(key, 31)[i]},
}
```

| 鍵 | 意味 |
|---|---|
| `parts` | 描く回路。`round` は必須、`keystep` は任意 |
| `reference` | `(plaintext, key, rounds)` を取る素の Python |
| `state` | ループする変数の名前。回路の `In` と一致させる |
| `vectors` | `(平文, 鍵, 暗号文)` の組。**論文の付録から** |
| `params(i, key)` | ラウンド i の引数。ラウンド鍵や定数 |
| `bit_order` | どちらの端をビット0とするか |

最後に登録します。

```python
REGISTRY = {c["name"]: c for c in (PRESENT, LLBC, ..., YOURS)}
```

### ビット順序

仕様書によって語のどちら側がビット0か違います。PRESENT は最下位から数えます
（pLayer が「入力ビット i が出力ビット 16i mod 63 へ」）。先頭桁をビット0と
書く論文もあります。

**取り違えると、鏡像の関数を計算する正常な回路ができます。** 回転が逆向き、置換が
逆写像。回路のどこにも異常はなく、層単体のテストでは捕まりません。

`bit_order` で明示してください。全部品が内部で変換するので、**論文の記法のまま
書けます。**

---

## 手順4 — 走らせる

```powershell
.\run.ps1 build   mycipher
.\run.ps1 verify  mycipher
.\run.ps1 analyse mycipher --rounds 3
```

`build` は回路を描き、使えない状態なら**そこで止まります**。

```
  round: this circuit is not usable yet
    no state variable found: a round circuit needs an In 'X' paired with
    an Out "X'" (or 'X_next'). inputs=['rk', 'state'] outputs=['out']
```

**`verify` を通らない回路は解析できません。** `analyse` も `cluster` も
`replicate` も拒否します。設計中で参照実装がまだ無い場合は `--unverified`
を付けてください。その場合の結果は回路の性質であって暗号の性質ではない、
とツールが明示します。

`verify` が3層を照合します。

```
  published vectors: 4/4
  circuit vs reference at 31 rounds: 8/8
```

**上の行が論文との一致、下の行が回路と参照実装の一致です。** 両方緑になって初めて
先へ進めます。

`--with-tests` を付けて `build` すると、生成された `.dig` に Testcase が埋め込まれ、
Digital で開いて **F8** を押せばその場で検証できます。

---

## よくある詰まり方

| 症状 | 原因 |
|---|---|
| `no state variable found` | `In "x"` と `Out "x'"` の対がない |
| `... is not wired` | 作った信号をどこにも繋いでいない |
| `xor operands differ in width` | 幅の違う値を XOR している |
| `net driven twice` | 同じポートを2箇所へ繋いだ、または部品が重なった |
| `published vectors: 0/N` | 参照実装が仕様と違う。**回路ではなく参照実装を疑う** |
| `circuit vs reference: 0/N` | 回路と参照実装が食い違う。`--with-tests` で F8 を見る |
| `DDT entries that are not powers of two` | S ボックスの DDT に 6 などがあり SAT では探索不可。GIFT がこれ |

最後の2つは意味が違います。**公開ベクタが落ちたら参照実装、回路との照合が落ちたら
回路**です。切り分けができるのがこの3層構造の利点です。

---

## お手本

`python/ciphers.py` の6つは、それぞれ違う要素を含むように選んであります。

| 暗号 | 構造 | 参考になる点 |
|---|---|---|
| **PRESENT-80** | SPN | ビット置換、80ビット鍵レジスタを `Wide` で描く |
| **GIFT-64-128** | SPN | ニブルの2ビットにしか届かないラウンド鍵 |
| **LLBC-128-128** | Feistel | 回転、2つの S ボックス層、鍵スケジュールも回路 |
| **Speck32/64** | ARX | `modadd` |
| **Simon32/64** | AND-RX | `gate("And", …)` |
| **SKINNY-64-128** | SPN | `mix_columns`、tweakey |

作りたい暗号に一番近いものをコピーして、S ボックスと定数を差し替えるところから
始めるのが早いと思います。GIFT は PRESENT のコピーでほぼ書けました。

---

## 仕様を確定させる

実装した6つのうち、**2つで仕様の読み違いをしました。**

Simon では鍵語の順序と z 系列のビット取り出し方向を両方間違え、SKINNY では
一度で通りました。Midori は定数が確定できず未完成のままです。

**どれも「暗号として動いてしまう」種類の誤り**です。テストベクタがなければ
気づけません。だから `vectors` を空にしないでください。

論文に付録がない場合は、参照実装を公開しているリポジトリを探すか、
CLAASP に同じ暗号があればそれと照合してください。

```python
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher
PresentBlockCipher().evaluate([0, 0])
```

CLAASP にある暗号なら、**暗号文だけでなく差分トレイルまで照合できます。**
それが最も強い検証です。
