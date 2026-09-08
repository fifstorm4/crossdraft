# CrossDraft を初めて動かす（Windows）

所要時間の目安: 手順1〜3 が待ち時間込みで 30〜50分。以降は各コマンド数秒〜数分。

---

## 手順 1 — 展開する

`crossdraft.tar.gz` をダウンロードしたら、PowerShell で。

```powershell
cd $HOME\Documents
mkdir crossdraft
tar -xzf $HOME\Downloads\crossdraft.tar.gz -C crossdraft
cd crossdraft
dir
```

**アーカイブをリポジトリの中に置かないでください。** `crossdraft.tar.gz` を
`C:\crossdraft` に置いて展開すると、その中にもう一組のツリーができます。Git は
それを追跡しますが CI は無視する（GitHub はルートの `.github/workflows` しか
読まない）ので、静かに古くなります。`$HOME\Downloads` から直接展開してください。

`Dockerfile`、`run.ps1`、`python`、`java`、`tests` が見えれば成功です。

Windows 10 以降なら `tar` は標準で入っています。無ければ 7-Zip で2回展開（`.gz` → `.tar`）してください。

---

## 手順 2 — Docker Desktop を起動する

タスクトレイのクジラのアイコンが動いていることを確認します。止まっていればスタートメニューから Docker Desktop を起動。

PowerShell で確認。

```powershell
docker version
```

`Server:` の行まで出れば準備完了です。`error during connect` なら Docker Desktop がまだ起動途中です。

**メモリ設定を確認してください。** SageMath のインストールが重いので、Docker Desktop の Settings → Resources → Memory を **4GB 以上**にしておくと安全です。

---

## 手順 3 — イメージをビルドする

```powershell
.\run.ps1 selftest
```

初回はイメージのビルドが走ります。**20〜40分**かかります。内訳は SageMath 系パッケージの取得が大半で、Kissat と NIST STS のコンパイルが続きます。

```
building crossdraft (once; SageMath makes this slow, allow 20-40 min)
```

`run.ps1` の実行がブロックされる場合は、その PowerShell セッションだけ許可します。

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

ビルドの最後に PRESENT を実行してテストベクタを照合します。ここで止まればイメージが壊れているので、**その状態では出荷されません**。

ビルドが終わると selftest が走ります。

```
  PASS  cross-validation against Digital  [79s]
  PASS  PRESENT against CLAASP's own model  [4s]
  PASS  randomised circuits  [144s]

  3/3 suites passed in 227s
  This installation reproduces the reference results.
```

**この3行が、あなたの PC で参照結果が再現されたという証拠です。** 私の環境の話ではありません。

---

## 手順 4 — PRESENT で一周してみる

いきなり LLBC に行かず、既知の暗号で挙動を確かめます。

```powershell
.\run.ps1 list
```

登録済みの暗号が出ます。

```powershell
.\run.ps1 build present
```

```
  round      244 components, 102 nets
  keystep     59 components,  17 nets
  -> /work/build/present
```

**`build\present\` フォルダが手元にできています。** エクスプローラで開くと `present_round.dig` があります。

```powershell
.\run.ps1 verify present --rounds 31
```

```
  published vectors: 4/4
  circuit vs reference at 31 rounds: 8/8
```

**回路が CHES 2007 の公開テストベクタと一致しました。**

```powershell
.\run.ps1 analyse present --rounds 3 --show --export fig.svg
```

```
  best differential characteristic over 3 rounds: weight 8.0
  active S-boxes at most: 4
  wrote /work/fig.svg
```

`fig.svg` がカレントディレクトリに出ています。ブラウザにドラッグすれば活性Sボックス図が見えます。

---

## 手順 5 — 回路を Digital で開いてみる

ここが一番手応えがあると思います。

1. Digital を起動（既にお持ちの `Digital.jar` をダブルクリック）
2. **File → Open**
3. `Documents\crossdraft\build\present\present_round.dig` を選ぶ

PRESENT のラウンド関数が回路図として表示されます。Sボックス16個、pLayer の64本配線、鍵加算。**これが CLAASP に渡っているものそのものです。**

`present_keystep.dig` も開いてみてください。80ビット鍵レジスタが2ポートに分かれ、61ビット回転が境界をまたいでいます。

**F8 でテストを実行**すれば、Digital 自身がこの回路を検証します。

---

## 手順 6 — LLBC を通す

```powershell
.\run.ps1 build llbc
.\run.ps1 verify llbc --rounds 20
```

```
  circuit vs reference at 20 rounds: 8/8
```

**まずここを確認してください。** これは「私が書いた LLBC 回路が、私が書いた参照実装と一致する」という意味です。仕様の解釈（Algorithm 1 の `R_i` 補正、MixWord の引数順）が貴論文と同じであることは、次の手順で確かめます。

```powershell
.\run.ps1 analyse llbc --rounds 3
```

3ラウンドで weight 8.0 が出れば、以前 CLAASP で確認した値と一致します。

---

## 手順 7 — 貴論文の Table VI を replicate する

**ここが本命です。** 論文のトレイルを、まったく別経路で作られたモデルに問い直します。

メモ帳で `table6.csv` を作り、`Documents\crossdraft` に保存します。

```
round,delta_L,delta_R
0,1800010000000000,BA60027201CE0012
1,0000000000000000,1800010000000000
2,1800010000000000,0000000000000000
3,37E0095401780004,1800010000000000
4,1800010000000000,37E0095401780004
5,0000000000000000,1800010000000000
6,1800010000000000,0000000000000000
7,BA60027201CE0012,1800010000000000
```

実行します。

```powershell
.\run.ps1 replicate llbc --trail table6.csv --rounds 7 --expect-weight 81
```

期待される出力。

```
  table6.csv: 8 states, replicating over 7 rounds of llbc
  input  difference 0x1800010000000000ba60027201ce0012
  output difference 0xba60027201ce00121800010000000000

  REPLICATED: weight 81.0 (probability 2^-81.0)
  published weight 81.0 -> MATCH
```

**一致すれば、STP で得た結果が、回路図から独立に構築されたモデルでも成立することの証拠になります。** 共有されたのは論文の数値だけです。

一致しなければ、どのラウンドで食い違うかを特定します。

```powershell
.\run.ps1 replicate llbc --trail table6.csv --rounds 7 --pin-all
```

全ラウンドを固定するので、**ソルバが最初に拒否したところ**が見るべき場所です。

---

## 手順 8 — 論文用の出力を取る

```powershell
.\run.ps1 env llbc
```

```
CrossDraft 0.1.0

environment
  Digital     present     java 21.0.12     CLAASP 3.0.0
  kissat      4.0.4       espresso present
  passagemath 10.8.11     host x86_64 Linux, 20 cores

circuits analysed
  llbc_round.json    sha256:...  298 components, 98 nets
  llbc_keystep.json  sha256:...   87 components, 30 nets
```

LaTeX の表にするなら。

```powershell
.\run.ps1 env llbc --latex > methodology.tex
```

**バージョンだけでなく回路のダイジェストが入ります。** 同じ CLAASP・同じソルバでも回路が1本の配線で違えば結果は変わるので、ダイジェストが「同じものを解析した」という主張を検証可能にします。

図と表も出せます。

```powershell
.\run.ps1 analyse llbc --rounds 3 --export fig3.svg --export fig3.pdf --export table.tex
.\run.ps1 sbox llbc --export ddt.tex
```

---

## つまずきそうなところ

| 症状 | 対処 |
|---|---|
| `run.ps1 は実行できません` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `error during connect` | Docker Desktop が起動しきっていない。1分待つ |
| ビルドが OOM で落ちる | Docker Desktop の Settings → Resources → Memory を 4GB 以上に |
| ビルドが数十分終わらない | 正常。SageMath の取得が大半 |
| `build/` が見えない | `.\run.ps1 build <暗号>` を先に実行 |
| 出力ファイルが見つからない | コンテナ内の `/work` は実行したディレクトリ。`cd` した場所に出ます |

---

## 起きたことを教えてください

特に知りたいのは次の3点です。

1. **イメージのビルドが通ったか。** 通らなければエラー全文を
2. **`selftest` が 3/3 になったか。** 私の環境以外で走るのは初めてです
3. **手順7の `replicate` が MATCH したか。** 不一致なら、それ自体が有益な発見です

私が気づいていない前提が、必ずどこかにあるはずです。
