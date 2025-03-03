#!/usr/local/bin/python3
#赛题一的额外维度目标分析，包括版本、POC提取等
import requests
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.prompts import PromptTemplate,ChatPromptTemplate
from langchain.chains import LLMChain, SimpleSequentialChain

from langchain.prompts import (
    ChatPromptTemplate,
    PromptTemplate,
    SystemMessagePromptTemplate,
    AIMessagePromptTemplate,
    HumanMessagePromptTemplate
)
from langchain.output_parsers import StructuredOutputParser, ResponseSchema
from langchain.schema import (
    AIMessage,
    HumanMessage,
    SystemMessage
)

import os
import json
import time
from bs4 import BeautifulSoup
import re

# prompt informations
HumanPrompt = PromptTemplate(
    template="""
                User question: if given some text and script from a html website, please summarize the following information:
                Vulnerability ID: The CVE ID corresponding to the vulnerability described in the article, in the format CVE-XXXX-XXXX. If there is no specific ID, it is NULL.
                Vendor or Product Name: The vendor or product name corresponding to the vulnerability described in the article. If both exist, take the vendor name.
                Software version number: The version number of the affected product device, usually appears in the form of "Tested Versions: ".
                Mitigation recommendations: Guidance on how to mitigate vulnerabilities, usually appears in the form of "Suggested Mitigations:".
                Extracted POC/EXP: Proof of Concept or Exploit extracted from the article, usually appears in the form of "Proof-of-Concept:".

s
                <context>
                {ocr_result}
                </context>
                answer user's question with the information in <context>
                output format: {format_instructions}

                let us analyse it step by step, give us your analyse procedure, and be careful about the following things:
                1.Check whether the "Affected Version(s)" field and the "Tested Version(s)" field exist in the article. If only "Affected Version(s)" or only "Tested Version(s)" exists, use it as the content of "Software version number". If both "Affected Version(s)" and "Tested Version(s)" exist, use the content of "Affected Version(s)" as the content of "Software version number".
                2.Check whether the "Suggested Mitigations" or "Mitigations" field  exists in the article. If so, use the content of "Suggested Mitigations" as the content of "Mitigation recommendations".If not, Summarize mitigation suggestions from the article as content of "Mitigation recommendations".
                3.Check whether the "Proof-of-Concept" field  exists in the article.If so, use the content of "Proof-of-Concept" as the content of "Extracted POC/EXP". If not, set field "Extracted POC/EXP" as NULL.
                4.Make sure all fields are fully extracted, especially "Proof-of-Concept".
                5.Output all the extracted fields in a complete JSON format without using referential sentences such as "See the Python script provided above."
            """,
    input_variables=["ocr_result","format_instructions"]
)
SystemPrompt = PromptTemplate(
    template="You are a cyber security engineer whose job is to look at vulnerability disclosure websites and summarize vulnerability information, you have the knowledge about CVE, poc(proof of concept) and exp(exploit), know all kinds of common-used programming language, and can read both English and Chinese.",
)

vender_str="PHP;Linksys;Google;Asus;华夏;Mongoose;OFFICE;Mail GPU;SnakeYAML;WebKit;Microsoft;OpenCart;Cajviewer;ZZCMS;Linux;Askey;Oracle;Github;Calibre;Typora;Bitrix24;bluetooth_stack;Foxit;Netgear;SolarWinds;TP-Link;Samsung;Adobe;Singtel;Acrobat;CS-Cart;Tesla;Apple;SEACMS;Shopware;Gitlab;Chamilo;Windows;LMS;Juniper;Qemu;OwnCloud;NULL;ChamiloLMS;Confluence;Apache;D-Link;F5;Prolink;Trend;Icecast;Hancom;Schneider;Mikrotik;Netatalk;NodeBB;Ivanti;Openwrt;Huawei;Dolibarr;KMPlayer;Android;EXIM;MarkText;Cisco;Razer;Obsidian;然之;Fortinet;Sudo"

program_str="JAVA;PHP;JAVASCRIPT;NULL;PYTHON;C;HTML;SHELL;C#;TYPESCRIPT;ASP;RUBY;C++"

sink_str="gets;scanf;strcpy;strcat;sprintf;vsprintf;stpcpy;wcscpy;memcpy;memmove;memset;printf;fprintf;vprintf;vfprintf;fscanf;fgets;input;array.array;eval;system;popen;exec;execl;execlp;execve;execvp;fork;os.system;subprocess.Popen;subprocess.call;subprocess.run;Runtime.exec;Runtime.getRuntime().exec;shell_exec;passthru;proc_open;do_system;mysql_query;mysqli_query;pg_query;sqlite3.execute;sqlite3_exec;psycopg2.execute;ActiveRecord.find_by_sql;prepare;unserialize;pickle.load;pickle.loads;cPickle.load;cPickle.loads;ObjectInputStream.readObject;Marshal.load;YAML.load;BinaryFormatter.Deserialize;Storable::thaw;open;fopen;readfile;file_get_contents;include;require;chmod;chown;os.chmod;os.chown;setuid;setgid;chroot;sleep;wait;tmpnam;tmpfile;tempnam;tempfile.mktemp;malloc;free;close;dup;ShellExecute;CreateProcess;strcpy;strcat;stpcpy;wcscpy;ActiveRecord.find_by_sql"

#output
response_schemas = [
    # ResponseSchema(name="cve", description="Vulnerability ID"),
    # ResponseSchema(name="vendor", description="Vendor or Product Name"),
    # ResponseSchema(name="language", description="Programming Language"),
    # ResponseSchema(name="trace_language", description="Backtrace Lanuage"),
    # ResponseSchema(name="is_cause", description="Is Cause Analysis"),
    # ResponseSchema(name="function", description="Dangerous Function Name"),
    # ResponseSchema(name="is_POC", description="Is POC/EXP"),
    # ResponseSchema(name="is_explain", description="Is POC/EXP Explanation"),
    # ResponseSchema(name="is_related", description="Is Related"),
    ResponseSchema(name="version", description="Software version number"),
    ResponseSchema(name="Recommendations", description="Mitigation recommendations"),
    ResponseSchema(name="POC/EXP", description="Extracted POC/EXP"),
]


def extract_text_from_html(html_file_path):
    # 读取HTML文件
    with open(html_file_path, 'r', encoding='utf-8') as file:
        html_content = file.read()

    # 使用BeautifulSoup解析HTML
    soup = BeautifulSoup(html_content, 'html.parser')

    for unwanted_tag in soup(['script', 'style', 'noscript', 'header', 'footer']):
        unwanted_tag.decompose()
    text = soup.get_text()
    lines = text.splitlines()
    non_empty_lines = [line.strip() for line in lines if line.strip()]
    output_text = "\n".join(non_empty_lines)
    return output_text


"""
Connect to the OpenAI API and return the response
"""
# 数据集所在的文件目录
#data_dir = '/vlun_demo'
data_dir = './data'
# 答案文件保存的目录
#answer_dir = '/result'
answer_dir = './result'
# 提示词
init_prompt = '''你的提示词'''

# chat_template = ChatPromptTemplate.from_messages(
#     [
#         ("system", "You are a cyber security engineer whose job is to look at vulnerability disclosure websites and compile vulnerability information."),
#         ("human", "Hello, how are you doing?"),
#         ("ai", "I'm doing well, thanks!"),
#         ("human", "{user_input}"),
#     ]
# )
# create SystemMessagePromptTemplate

SystemMessagePrompt = SystemMessagePromptTemplate(prompt=SystemPrompt)
# create HumanMessagePromptTemplate

HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPrompt)
# conbine Prompt
chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

output_parser = StructuredOutputParser.from_response_schemas(response_schemas)

format_instructions = output_parser.get_format_instructions()

def read_words_from_file(file_path, num_words):
    words = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                words.extend(line.split())
                words.append('\n')
                if len(words) >= num_words:
                    break
        return ' '.join(words[:num_words])
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return ""
    except Exception as e:
        print(f"An error occurred: {e}")
        return ""


def llm_api_test(prompt):
    llm = ChatOpenAI(
        streaming=True,
        verbose=True,
        # key和base开赛后提供
        openai_api_key='6ad9127594fa1951b18de59fa8ecb856',
        openai_api_base='https://poc.qianxin.com',
        model_name='tq-gpt',
        timeout=300
    )
    chain=LLMChain(llm=llm, prompt=chat_template)
    try:
        output = chain.run(ocr_result=prompt,format_instructions=format_instructions,vender_list=vender_str,language_list=program_str)
        print(output)
        json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        return None

def func(input, output):
    root_dir = 'data'
    
    files = os.listdir(root_dir)

    # 仅选择数字命名的文件
    numeric_files = [f for f in files if f.isdigit()]

    # 按数字大小排序文件名
    sorted_files = sorted(numeric_files, key=int)

    for file in sorted_files:
        #print(file)
        file_path = root_dir+'/'+file
        #print(file_path)
        result_string = extract_text_from_html(file_path) 
        #print(result_string)
        json_out=llm_api_test(result_string)
        while json_out==None:
            print("error: return is None, try again")
            json_out=llm_api_test(result_string)
        
   
        print("json_out",json_out)
        json_str = json.dumps(json_out, indent=4)
        print("json_str",json_str)
        with open('output.txt', 'a') as f:
            f.write(json_str)

if __name__ == '__main__':
    func(data_dir, answer_dir)