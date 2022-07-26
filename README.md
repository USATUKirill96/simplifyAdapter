# VirusTotal scanner


## Setup

Setup local virtualenv

```shell
python3 -m virtualenv venv
source venv/bin/activate
```

Install required libraries
```shell
pip install -r requirements.txt
```


## Input data

### Domains
Directory `/examples` contains json files with domains. Each file must follow the structure:

```json
{
  "domains": ["domain1.com", "domain2.com"]
}
```

### .env
.env must follow the structure listed in `.env.example` file. 
You need to get an api_key. You need an account (it's free) to obtain it. [register](https://www.virustotal.com/gui/my-apikey)


## Run

Use comand 

```shell
python3 main.py examples 10
```

where 
- `examples` - path to the directory with json files
- `10` - number of domains which will be parsed
