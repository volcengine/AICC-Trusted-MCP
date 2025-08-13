#!/usr/bin/env bash

set -o errexit -o pipefail -o xtrace

cd -- "$(dirname -- "$0")"

# https://packaging.python.org/en/latest/tutorials/packaging-projects/

# 清理旧版本包
shopt -s nullglob
rm -rf build dist *.egg-info

# 安装依赖项
if ! python -c 'import build' 2>&1 >/dev/null; then
  pip install --upgrade pip
  pip install --upgrade build
fi

# 执行构建 (后续构建可以只执行这一命令)
python -m build

# 检查包内容
shopt -s failglob
ls -l dist
if command -v tar 2>&1 >/dev/null; then
  tar tf dist/*.tar.gz
fi
if command -v unzip 2>&1 >/dev/null; then
  unzip -l dist/*.whl
fi