# AIJON

# Requirements

## Apt packages
```bash
apt -y install python3 python3-dev curl git python3-pip rsync
```

## Pip packages
```bash
pip3 install pyyaml
```

## Other
Install UV

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

You also need to install IDA and set the IDA_PATH environment variable to the root IDA directory.

```bash
export IDA_PATH=<path/to/ida>
```

If not, we fall back to using `angr`.

## LLM API keys

```bash
export OPENAI_API_KEY=<your_key>
export ANTHROPIC_API_KEY=<your_key>
export USE_LLM_API=0
```

# Docker

`docker build -t aijon .`

# Running experiments

```bash
./tests/test_container.sh <ID>
```
You can find valid ID's from `experiments/experiment_mapping.csv`

Replace `$HOME/projects/aijon` in the `tests/test_container.sh` to a directory on your machine that contains the IDA installation.

