#!/usr/local/bin/python3
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
import tiktoken
import os
import json
import time
from bs4 import BeautifulSoup
import re
import csv

# 数据集所在的文件目录
data_dir = '/data'
#data_dir = './data'
# 答案文件保存的目录
answer_dir = '/result'
#answer_dir = './result'
env_vars = os.environ
key_env=env_vars['API_KEY']
base_env=env_vars['API_BASE']
#8bb73128d0b5732a1e0723f922245df8
#key_env=''
#base_env='https://poc.qianxin.com'
# prompt informations
HumanPromptFormer = PromptTemplate(
    template="""
                User question: if given some text and script from a html website, please summarize the following information:
                Vulnerability ID: The CVE ID corresponding to the vulnerability described in the article, in the format CVE-XXXX-XXXX. If there is no specific ID, it is NULL.
                Vendor or Product Name: The vendor or product name corresponding to the vulnerability described in the article. If both exist, take the vendor name.
                Programming Language: The programming language used by the object with the vulnerability. If multiple languages are involved, take the language where the vulnerability point is located.
                Backtrace Lanuage: The programming language suggested by back trace chain or stack trace chain, default is NULL if there is no back trace chain.
                Is Cause Analysis: Whether the article contains an explanation of the cause of the vulnerability. TRUE if yes, FALSE if no.
                Dangerous Function: Directly-mentioned dangerous function that triggers the vulnerability described in the article, such as memmove, do_system. If there is no such function, it is NULL.
                
                <context>
                {ocr_result}
                </context>
                answer user's question with the information in <context>
                output format: {format_instructions}

                let us analyse it step by step, give us your analyse procedure, and be careful about the following things:
                1.if there are many CVE IDs in an article, only output one CVE ID that is most relevant to the text;
                2.all vendor that you need to check is listed in {vender_list}, different items are separated with ';', NULL means no vender or product name are found;
                3.
                4.if many vendors are located, only output one vender that is closed to the CVE ID information and is directly mentioned(eg: output Android instead of Google if find "Android" in text but no "google" in text);
                5.all programming languages that you need to check is listed in {language_list}, different items are separated with ';', NULL means no other languages are found, your Programming Language output must be in the list;
                6.
                7.If there are many programming languages found, output the language that is most relevant to the vulnerability trigger point(near the Dangerous Function output); 
                8.Dangerous function must be directly mentioned in the text, you can use some content relevant to the dangerous function if it is not directly found(eg: output telnet if there is no system);
                9.Regard "Is Cause Analysis" to be true when the article describes the code near a dangerous function(Attacking codes such as PoC is not this type of code), return FALSE if there are no content about code nearing dangerous function;
                10.
                11.
            """,
    input_variables=["ocr_result","format_instructions","vender_list","language_list"]
)
HumanPromptLater = PromptTemplate(
    template="""
                User question: if given some text and script from a html website, please summarize the following information:
                POC/EXP Presence: Determine if the article contains a Proof of Concept (POC) or exploit code (EXP). If present, output TRUE; otherwise, output FALSE.
                POC/EXP Explanation: Identify whether the article provides an explanation or commentary about the POC/EXP code. If explanations exist, output TRUE; otherwise, output FALSE.
                Is Related: Whether the article is related to vulnerability mining. If it is not related to vulnerability mining or does not involve specific vulnerabilities, return FALSE, otherwise, return TRUE.

                <context>
                {ocr_result}
                </context>
                answer user's question with the information in <context>
                output format: {format_instructions}


                let us analyse it step by step, give us your analyse procedure, and be careful about the following things:
                1. Is related should be TRUE if the article is about a certain vulnerability(eg:has a CVE id);
                2. Is related should be FALSE if the article describes cyber security, but do not describe vulnerability mining(eg: it describes virus);
                3. If the article contains a functional code snippet, a series of steps or instructions, or commands that demonstrate how to exploit a vulnerability, carry out an attack, or crash the vulnerable system, mark POC/EXP Presence as TRUE; otherwise, mark it as FALSE.

                4. Step 4.1-4.4 are used for POC/EXP Explanations:
                4.1 POC/EXP Explanation requires a field-by-field explanation of each parameter or field involved in the POC/EXP, and this explanation must be separate from the POC code block;
                4.2 The explanation must detail all fields or parameters (e.g., HTTP headers, input parameters, function arguments) and cannot rely on common commands (e.g., telnet, curl) or explain only one field;
                4.3 If the explanation does not meet these criteria or is not separate from the POC code block, mark POC/EXP Explanation as FALSE;
                4.4 POC/EXP Explanations are text close to POC/EXP(code itself is not explaination), comment of code is also regarded as explainations.

                5. Focused Analysis:
                5.1. Pay attention to both the presence of POC/EXP and the presence of explanation.
                5.2. When POC/EXP Presence is TRUE, verify if there is enough explanation to mark POC/EXP Explanation as TRUE.
                5.3. If the code is present but lacks detailed explanation or commentary about the specific fields in the POC/EXP, mark POC/EXP Explanation as FALSE.

                6.please ensure that the output json is a legal json file, and output your analyse procedure.

            """,
    input_variables=["ocr_result","format_instructions"]
)
SystemPrompt = PromptTemplate(
    template="You are a cyber security engineer whose job is to look at vulnerability disclosure websites and summarize vulnerability information, you have the knowledge about CVE, poc(proof of concept) and exp(exploit), know all kinds of common-used programming language, and can read both English and Chinese.",
)

vender_str="PHP;Linksys;Google;Asus;华夏;Mongoose;OFFICE;Mail GPU;SnakeYAML;WebKit;Microsoft;OpenCart;Cajviewer;ZZCMS;Linux;Askey;Oracle;Github;Calibre;Typora;Bitrix24;bluetooth_stack;Foxit;Netgear;SolarWinds;TP-Link;Samsung;Adobe;Singtel;Acrobat;CS-Cart;Tesla;Apple;SEACMS;Shopware;Gitlab;Chamilo;Windows;LMS;Juniper;Qemu;OwnCloud;NULL;Confluence;Apache;D-Link;F5;Prolink;Trend;Icecast;Hancom;Schneider;Mikrotik;Netatalk;NodeBB;Ivanti;Openwrt;Huawei;Dolibarr;KMPlayer;Android;EXIM;MarkText;Cisco;Razer;Obsidian;然之;Fortinet;Sudo"

program_str="JAVA;PHP;JAVASCRIPT;NULL;PYTHON;C;HTML;SHELL;C#;TYPESCRIPT;ASP;RUBY;C++"

sink_str="gets;scanf;strcpy;strcat;sprintf;vsprintf;stpcpy;wcscpy;memcpy;memmove;memset;printf;fprintf;vprintf;vfprintf;fscanf;fgets;input;array.array;eval;system;popen;exec;execl;execlp;execve;execvp;fork;os.system;subprocess.Popen;subprocess.call;subprocess.run;Runtime.exec;shell_exec;proc_open;do_system;ShellExecute;CreateProcess"

#output
response_schemas_former = [
    ResponseSchema(name="cve", description="Vulnerability ID"),
    ResponseSchema(name="vendor", description="Vendor or Product Name"),
    ResponseSchema(name="language", description="Programming Language"),
    ResponseSchema(name="trace_language", description="Backtrace Lanuage"),
    ResponseSchema(name="is_cause", description="Is Cause Analysis"),
    ResponseSchema(name="function", description="Dangerous Function Name"),
    #ResponseSchema(name="is_POC", description="Is POC/EXP"),
    #ResponseSchema(name="is_explain", description="Is POC/EXP Explanation"),
    #ResponseSchema(name="is_related", description="Is Related"),
]
response_schemas_later = [
    #ResponseSchema(name="cve", description="Vulnerability ID"),
    #ResponseSchema(name="vendor", description="Vendor or Product Name"),
    #ResponseSchema(name="language", description="Programming Language"),
    #ResponseSchema(name="is_cause", description="Is Cause Analysis"),
    #ResponseSchema(name="function", description="Dangerous Function Name"),
    ResponseSchema(name="is_POC", description="Is POC/EXP"),
    ResponseSchema(name="is_explain", description="Is POC/EXP Explanation"),
    ResponseSchema(name="is_related", description="Is Related"),
]

length_limit=18000
def get_tokenizer(model_name='gpt-3.5-turbo'):
    encoding = tiktoken.encoding_for_model(model_name)
    return encoding

# 计算文本的 token 数量
def tokenize(text, tokenizer=None):
    if tokenizer is None:
        tokenizer = get_tokenizer()
    
    # 使用 tokenizer 进行文本编码并返回 token 数量
    tokens = tokenizer.encode(text)
    return len(tokens)

def split_prompt(prompt, max_tokens, tokenizer=None):
    # 获取tokenizer
    encoding = tokenizer or get_tokenizer()
    
    # 对输入文本进行 token 化
    prompt_tokens = encoding.encode(prompt)
    
    # 仅取前 max_tokens 个 token
    prompt_tokens = prompt_tokens[:max_tokens]  # 只保留前 max_tokens 个 token

    # 返回 token 数量不超过 max_tokens 的文本块
    chunks = []
    if prompt_tokens:
        chunks.append(encoding.decode(prompt_tokens))
    
    return chunks[0]

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


def check_output_regex(output):
    pattern = r"maximum context length is 8000 tokens"
    if re.search(pattern, output):
        return 1
    else:
        return 0

def llm_api_test_former(prompt):
    global length_limit
    llm = ChatOpenAI(
        streaming=True,
        verbose=True,
        # key和base开赛后提供
        openai_api_key=key_env,
        openai_api_base=base_env,
        model_name='tq-gpt',
        timeout=300
    )
    # create HumanMessagePromptTemplate
    HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPromptFormer)
    # conbine Prompt
    chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas_former)

    format_instructions = output_parser.get_format_instructions()
    if len(prompt)>length_limit:
        prompt = prompt[:length_limit]

    chain=LLMChain(llm=llm, prompt=chat_template)
    try:
        output = chain.run(ocr_result=prompt,format_instructions=format_instructions,vender_list=vender_str,language_list=program_str)
        print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        for i in range(10):
            if json_out["cve"] and json_out["vendor"] and json_out["language"] and json_out["trace_language"] and json_out["is_cause"] and json_out["function"]:
                break
            output = chain.run(ocr_result=prompt,format_instructions=format_instructions,vender_list=vender_str,language_list=program_str)
            #print(output)
            json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        if check_output_regex(str(e)) == 1:
            length_limit = length_limit - 2000
        return None

def llm_api_test_later(prompt):
    global length_limit
    llm = ChatOpenAI(
        streaming=True,
        verbose=True,
        # key和base开赛后提供
        openai_api_key=key_env,
        openai_api_base=base_env,
        model_name='tq-gpt',
        timeout=300
    )
    # create HumanMessagePromptTemplate
    HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPromptLater)
    # conbine Prompt
    chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas_later)

    format_instructions = output_parser.get_format_instructions()
    if len(prompt)>length_limit:
        prompt = prompt[:length_limit]
    
    try:
        output = chain.run(ocr_result=prompt,format_instructions=format_instructions)
        print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        for i in range(10):
            if json_out["is_POC"] and json_out["is_explain"] and json_out["is_related"]:
                break
            output = chain.run(ocr_result=prompt,format_instructions=format_instructions)
            json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        if check_output_regex(str(e)) == 1:
            length_limit = length_limit - 2000
        return None

def former_once(result_string):
    global length_limit
    length_limit = 18000
    json_out_former=llm_api_test_former(result_string)
    for i in range(50):
        if json_out_former!=None:
            break
        json_out_former=llm_api_test_former(result_string)
    print(json_out_former)
    return json_out_former
    
def later_once(result_string):
    global length_limit
    length_limit = 18000
    json_out_later=llm_api_test_later(result_string)
    for i in range(50):
        if json_out_later!=None:
            break
        print("error: return is None, try again")
        json_out_later=llm_api_test_later(result_string)
    return json_out_later

vender_relations=[
    ("OFFICE", "Microsoft"),
    ("Askey", "Asus"),
    ("Acrobat", "Adobe"),
    ("Github", "Microsoft"),
    ("Android", "Google"),
    ("Confluence", "Atlassian")
]
cpp_syms=["::","namespace","cpp","templete ","class ","iostream","catch (std::exception &e)","cin >>","cout <<","virtual "]
def vote_ask(input, output):
    fout=open(output+"/res.csv",'w',newline='')
    #writer = csv.writer(fout,delimiter=';')
    root_dir = input
    
    files = os.listdir(root_dir)

    # 仅选择数字命名的文件
    numeric_files = [f for f in files if f.isdigit()]

    # 按数字大小排序文件名
    sorted_files = sorted(numeric_files, key=int)

    for file in sorted_files:
        try:
            print(file)
            file_path = root_dir+'/'+file
            print(file_path)
            result_string = extract_text_from_html(file_path) 
            print(result_string)
            json_out_former=former_once(result_string)
            json_out_former2=former_once(result_string)
            json_out_former3=None
            vender_list = vender_str.split(';')
            program_list = program_str.split(';')
            #vote
            if json_out_former["vendor"] not in vender_list and json_out_former2["vendor"] in vender_list:
                json_out_former["vendor"]=json_out_former2["vendor"]
            elif json_out_former["vendor"] not in vender_list and json_out_former2["vendor"] not in vender_list:
                json_out_former3=former_once(result_string)
                if json_out_former3["vendor"] in vender_list:
                    json_out_former["vendor"]=json_out_former3["vendor"]
            if json_out_former["vendor"] != json_out_former2["vendor"]:
                if not json_out_former3:
                    json_out_former3=former_once(result_string)
                if json_out_former2["vendor"] == json_out_former3["vendor"]:
                    json_out_former["vendor"]=json_out_former2["vendor"]
            
            vendor = json_out_former.get("vendor", "").lower()
            for a, b in vender_relations:
                a_lower, b_lower = a.lower(), b.lower()
                # 正向匹配：如果 vendor 是元组的第一个，且第二个出现在文本中
                if vendor == a_lower and b_lower in result_string.lower():
                    json_out_former["vendor"] = b  # 修改为元组的第二个值
                    break
                elif vendor == b_lower and b_lower in result_string.lower():
                    pass
                # 反向匹配：如果 vendor 是元组的第二个，且第一个出现在文本中
                elif vendor == b_lower and a_lower in result_string.lower():
                    json_out_former["vendor"] = a  # 修改为元组的第一个值
                    break

            if json_out_former["language"] != json_out_former2["language"]:
                if not json_out_former3:
                    json_out_former3=former_once(result_string)
                if json_out_former2["language"] == json_out_former3["language"]:
                    json_out_former["language"]=json_out_former3["language"]
            for json in [json_out_former,json_out_former2]:
                if json["trace_language"]=="C":
                    for sym in cpp_syms:
                        if sym in result_string:
                            json["trace_language"]=="C++"
                            break
                elif json["trace_language"]=="C++":
                    find_sym=False
                    for sym in cpp_syms:
                        if sym in result_string:
                            find_sym=True
                            break
                    if not find_sym:
                        json["trace_language"]=="C"
            if json_out_former["trace_language"] != json_out_former2["trace_language"]:
                if not json_out_former3:
                    json_out_former3=former_once(result_string)
                if json_out_former2["trace_language"] == json_out_former3["trace_language"]:
                    json_out_former["trace_language"]=json_out_former3["trace_language"]
            if json_out_former["is_cause"] != json_out_former2["is_cause"]:
                if not json_out_former3:
                    json_out_former3=former_once(result_string)
                if json_out_former2["is_cause"] == json_out_former3["is_cause"]:
                    json_out_former["is_cause"]=json_out_former3["is_cause"]
            if json_out_former["cve"] != json_out_former2["cve"]:
                if not json_out_former3:
                    json_out_former3=former_once(result_string)
                if json_out_former2["cve"] == json_out_former3["cve"]:
                    json_out_former["cve"]=json_out_former3["cve"]
            if json_out_former["function"] != json_out_former2["function"]:
                if not json_out_former3:
                    json_out_former3=former_once(result_string)
                if json_out_former2["function"] == json_out_former3["function"]:
                    json_out_former["function"]=json_out_former3["function"]
            json_out_later=later_once(result_string)
            json_out_later2=later_once(result_string)
            json_out_later3=later_once(result_string)
            json_out_later4=later_once(result_string)
            
            

 #vote
            related_vote=0
            if json_out_later['is_related'] == "FALSE":
                related_vote+=1
            if json_out_later2['is_related'] == "FALSE":
                related_vote+=1
            if json_out_later3['is_related'] == "FALSE":
                related_vote+=1
            if json_out_later4['is_related'] == "FALSE":
                related_vote+=1
                                

            if json_out_later2['is_POC']=="TRUE" and json_out_later2["is_explain"]=="FALSE":
                json_out_later=json_out_later2
            if json_out_later3['is_POC']=="TRUE" and json_out_later3["is_explain"]=="FALSE":
                json_out_later=json_out_later3
            if json_out_later4['is_POC']=="TRUE" and json_out_later4["is_explain"]=="FALSE":
                json_out_later=json_out_later4
            
            if json_out_later['is_POC']=="FALSE" and json_out_later["is_explain"]=="TRUE":
                json_out_later["is_explain"]=="FALSE"
                    
                    
                    
            if related_vote >= 2:
                json_out_later['is_related'] = "FALSE"
            else:
                json_out_later['is_related'] = "TRUE"
            sink_list = sink_str.split(';')
            print("json",json_out_former,json_out_later)
            csv_row=[]
            #output
            if json_out_later['is_related']=="FALSE":
                csv_row=[file,"NULL","NULL","NULL","NULL","NULL","NULL","NULL"]
            else:
                #csv_row.append(file)
                csv_row.append(json_out_former["cve"])
                csv_row.append(json_out_former["vendor"])
                if json_out_former["trace_language"] != "NULL" and json_out_former["trace_language"] != json_out_former["language"]:
                    csv_row.append(json_out_former["trace_language"])
                else:
                    csv_row.append(json_out_former["language"])
                csv_row.append(json_out_former["is_cause"].upper())
                if json_out_former["function"] in sink_list and json_out_former["function"] in result_string:
                    csv_row.append(json_out_former["function"])
                else:
                    csv_row.append("NULL")
                csv_row.append(json_out_later["is_POC"].upper())
                csv_row.append(json_out_later["is_explain"].upper())

                if json_out_former["cve"]=='NULL' and json_out_former["vendor"]=='NULL' and json_out_former["is_cause"]=='FALSE' and json_out_later["is_POC"]=="FALSE":
                    csv_row=[file,"NULL","NULL","NULL","NULL","NULL","NULL","NULL"]
            writer.writerow(csv_row)
            fout.flush()
        except Exception as e:
            print("analysing file error",e)
    fout.close()

if __name__ == '__main__':
    vote_ask(data_dir, answer_dir)
