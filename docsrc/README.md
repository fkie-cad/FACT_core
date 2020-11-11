# Building the FACT Documentation Locally

## Installing the Requirements

```shell script
python3 -m pip install -r doc_dependencies.txt
```

or 

```shell script
pip3 install -r doc_dependencies.txt
```

depending on your python / pip version / preference.


## Building the Docs

```shell script
make clean html
```

## Viewing the Built Docs

```shell script
firefox _build/html/index.html
```
