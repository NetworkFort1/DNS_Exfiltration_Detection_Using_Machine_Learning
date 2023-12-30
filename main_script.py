
import pandas as pd
import numpy as np
import pickle as pkl
import zat
from zat.log_to_dataframe import LogToDataFrame
from urlextract import URLExtract
import re
import wordninja
from collections import Counter
import math
import subprocess



def clean_url(data):
    extractor = URLExtract()
    urls = data['query'].apply(lambda x: ' '.join(extractor.find_urls(x)) if extractor.find_urls(x) else x)
    return urls

def calculate_character_frequency(a):
    char_frequency = Counter(a)
    total_characters = len(a)
    entropy = -sum((freq / total_characters) * math.log2(freq / total_characters) for freq in char_frequency.values())
    return entropy

def calculate_unique(data):
    arr = []
    for i in range(len(data)):
        t_ts = []
        for j in range(i, i - 10, -1):
            ts = ""
            if j >= 0:
                ts = ".".join(data['query'][j].split('.')[:-2])
            ts = set(ts)
            t_ts.append(ts)

        intersection = t_ts[-1]
        union = t_ts[-1]
        for j in range(len(t_ts) - 1):
            intersection = intersection & t_ts[j]
            union = union | t_ts[j]
        intersection_size = len(intersection)
        union_size = len(union)

        arr.append(0 if union_size == 0 else (1 - (intersection_size / union_size)))

    return arr

def calculate_metrics(data):
    data['length'] = data['query'].apply(lambda x: len(".".join(x.split('.')[:-2])))
    data['subdomains_count'] = data['query'].apply(lambda x: x.count('.') - 1 if x.count('.') >= 2 else 0)
    data['w_count'] = data['query'].apply(lambda x: len(wordninja.split(".".join(x.split('.')[:-2]))))
    data['w_max'] = data['query'].apply(lambda x: 0 if not len(".".join(x.split('.')[:-2])) else len(max(wordninja.split(".".join(x.split('.')[:-2])), key=len)))
    data['entropy'] = data['query'].apply(lambda x: calculate_character_frequency(".".join(x.split('.')[:-2])))
    data['w_max_ratio'] = data['w_max'] / data['length']
    data['w_count_ratio'] = data['w_count'] / data['length']
    data['digits_ratio'] = data['query'].apply(lambda x: 0 if not len(".".join(x.split('.')[:-2])) else sum(1 for char in x.split('.')[-2] if char.isdigit()) / len(".".join(x.split('.')[:-2])))
    data['uppercase_ratio'] = data['query'].apply(lambda x: 0 if not len(".".join(x.split('.')[:-2])) else sum(1 for letter in x.split('.')[-2] if letter.isupper()) / len(".".join(x.split('.')[:-2])))
    data['time_avg'] = data['ts'].rolling(window=10, min_periods=1).apply(lambda x: np.mean(np.diff(x)))
    data['time_stdev'] = data['ts'].rolling(window=10, min_periods=1).apply(lambda x: np.std(np.diff(x)))
    data['size_avg'] = data['length'].rolling(window=10, min_periods=1).mean()
    data['size_stdev'] = data['length'].rolling(window=10, min_periods=1).std()
    data['unique'] = calculate_unique(data)
    data['entropy_avg'] = data['entropy'].rolling(window=10, min_periods=1).mean()
    data['entropy_stdev'] = data['entropy'].rolling(window=10, min_periods=1).std()

    return data
path ='/opt/zeek/spool/zeek/dns.log'
#path="/content/drive/MyDrive/DNS Exfiltration attack dataset /dns.log"
try:
    try:
        filename = 'DNS_Exfiltration_model.sav'
        loaded_model = pkl.load(open(filename, 'rb'))
    except Exception as e:
        raise Exception(e)

    log_to_df = LogToDataFrame()
    print("Starting Files Data Loading")
    if path:
        # with subprocess.Popen(['tail', '-f', '-n', '200', path], stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as proc:
        with open(path) as f:
            for line in f:
            # for line in proc.stdout:

                line = line.rstrip('\n')
                if line and line[0] != '#':
                    ts = line.split('\t')[0]
                    query = line.split('\t')[9]

                    dns_log = pd.DataFrame({'ts': [ts], 'query': [query]})
                    dns_log=dns_log.dropna()

                    dns_log['query'] = clean_url(dns_log)
                    dns_log=dns_log.dropna()
                    
                    if dns_log.empty or dns_log.iloc[0]['query'].count('.') < 2:
                        print("Not important")
                        continue

                    print(dns_log)

                    dns_log = dns_log.reset_index()
                    dns_log = calculate_metrics(dns_log)

                    print(dns_log.isnull().sum())

                    dns_log = dns_log.dropna()

                    if dns_log.empty:
                        print("Important")
                        continue

                    dns_log_copy = dns_log.copy()

                    dns_log.rename(columns={'ts': 'timestamp'}, inplace=True)
                    dns_log = dns_log.drop(['index','query'],axis=1)

                    print(dns_log)
                    y_predict = loaded_model.predict(dns_log)
                    dns_log_copy['attack'] = y_predict

                    print(dns_log_copy)

except Exception as e:
    print(f"Error occurred while loading log files: {e}")
    exit()

