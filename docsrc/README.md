# Building the FACT Documentation Locally

## Building the Docs

The documentation dependencies are the `docs` dependency group in `pyproject.toml`.
[uv](https://docs.astral.sh/uv/) installs them and builds the docs with:

```shell script
uv run --only-group docs make clean html
```

## Viewing the Built Docs

```shell script
firefox _build/html/index.html
```
