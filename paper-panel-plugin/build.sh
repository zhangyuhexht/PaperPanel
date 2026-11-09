#!/usr/bin/env bash
# PaperPanel 插件构建脚本（Git Bash / Linux / macOS）
# 首次运行会自动把编译期依赖下载到 lib/（lib/ 与 out/ 不入库），输出 PaperPanel.jar
#
# 注意：paper-api 26.3 是 Java 25 字节码，需要 JDK 25 的 javac 才能读取；
#       脚本产出的是 --release 21 的字节码。
set -e
cd "$(dirname "$0")"

JAVAC="${JAVAC:-javac}"
JAR="${JAR:-jar}"
if ! command -v "$JAVAC" >/dev/null 2>&1; then
  # 常见 JDK 25 位置（Windows / IntelliJ 自动安装的 JDK）
  for p in "$HOME/.jdks"/jdk-*/bin/javac.exe "/c/Program Files/Java"/jdk-*/bin/javac.exe; do
    [ -f "$p" ] && JAVAC="$p" && JAR="$(dirname "$p")/jar.exe" && break
  done
fi

PAPER_REPO="https://repo.papermc.io/repository/maven-public"
CENTRAL="https://repo1.maven.org/maven2"

# 编译期依赖（均由服务端在运行时提供，不打进插件 jar）
DEPS=(
  "paper-api.jar|$PAPER_REPO/io/papermc/paper/paper-api/26.3.build.244-stable/paper-api-26.3.build.244-stable.jar"
  "log4j-api.jar|$CENTRAL/org/apache/logging/log4j/log4j-api/2.17.1/log4j-api-2.17.1.jar"
  "log4j-core.jar|$CENTRAL/org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar"
  "adventure-api.jar|$CENTRAL/net/kyori/adventure-api/5.2.0/adventure-api-5.2.0.jar"
  "adventure-key.jar|$CENTRAL/net/kyori/adventure-key/5.2.0/adventure-key-5.2.0.jar"
  "adventure-plain.jar|$CENTRAL/net/kyori/adventure-text-serializer-plain/5.2.0/adventure-text-serializer-plain-5.2.0.jar"
  "examination-api.jar|$CENTRAL/net/kyori/examination-api/1.3.0/examination-api-1.3.0.jar"
  "annotations.jar|$CENTRAL/org/jetbrains/annotations/24.1.0/annotations-24.1.0.jar"
)

mkdir -p lib
for entry in "${DEPS[@]}"; do
  name="${entry%%|*}"
  url="${entry#*|}"
  if [ -s "lib/$name" ]; then continue; fi
  echo "[deps] downloading $name ..."
  if ! curl -fsSL --retry 2 -o "lib/$name" "$url"; then
    echo "[deps] FAILED: $url" >&2
    rm -f "lib/$name"
    exit 1
  fi
done

case "$(uname)" in
  *MINGW*|*MSYS*|*CYGWIN*) SEP=";" ;;
  *) SEP=":" ;;
esac

CP=""
for entry in "${DEPS[@]}"; do
  CP="${CP:+$CP$SEP}lib/${entry%%|*}"
done

rm -rf out && mkdir -p out
"$JAVAC" --release 21 -encoding UTF-8 -Xlint:-options -cp "$CP" -d out src/mcpanel/*.java

cp src/plugin.yml src/config.yml out/
cp -r src/web out/
"$JAR" cf PaperPanel.jar -C out .
echo "BUILD_OK -> $(pwd)/PaperPanel.jar"
