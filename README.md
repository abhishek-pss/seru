python3 -m venv venv

source venv/bin/activate


# 1. Install dependencies
pip install requests rich pyyaml

# 2. Save the script as serverwatch.py

# 3. Run it once to generate the default config
python serverwatch.py --one-shot
# → Creates servers.yml — edit it with your own targets

# 4. Edit servers.yml (example content shown below)
