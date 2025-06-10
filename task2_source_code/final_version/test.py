#!/usr/local/bin/python3
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
from Splitting_function_CC import process_c_files
from Splitting_function_py import process_python
from Splitting_function_php import process_php_files_in_directory
from Splitting_function_java import process_java_files
from Splitting_function_go import extract_functions_with_receivers
from Splitting_jsp import split_jsp_files
from arbitrary import check_arbitrary,check_output_regex
from bypass1 import check_bypass
from int_overflow1 import check_int_overflow
from bof_memory1 import check_bof
from others_memory import check_others
from command_memory import check_command
import os
import json
import time
from bs4 import BeautifulSoup
import re
import csv
import re
# 数据集所在的文件目录
data_dir = '/vlun_demo'
#data_dir = './data40'

# 答案文件保存的目录
answer_dir = '/result'
#answer_dir = './result'
env_vars = os.environ

key_env=env_vars['API_KEY']
base_env=env_vars['API_BASE']
#key_env=''
#base_env='https://poc.qianxin.com'

# prompt informations
HumanPromptStep1 = PromptTemplate(
    template="""
                User question: If you provide a code snippet to be verified, the language of the code snippet is {slice_lang}, and the code snippet may contain a vulnerability of type {slice_vul}, please summarize the following information as much as possible:
                "vul_functions": the function names of the {slice_vul} vulnerability type in the code snippet.
                "related_functions": other function names related to the dangerous function in the code snippet.

                <context>
                {ocr_result}
                </context>
                Use <context> Answer the user's question with the information in
                Output format: {format_instructions}

                Let's analyze step by step and give us your analysis process. Pay attention to the following points:
                1. The code snippet provided may be related to the {slice_vul} vulnerability or may not be related to the {slice_vul} vulnerability;
                2. If the code snippet provided is related to the {slice_vul} vulnerability, the output dangerous function and other related functions may be more than one;
                3. If the code snippet provided is not related to the {slice_vul} vulnerability, the output "vul_functions" is NULL, and the "related_functions" is also NULL;
                4. Please analyze from the perspective of the function call chain Analyze the code snippet provided, and save other functions in the same function call chain as the dangerous function in the "related_functions";
                5. Please analyze the functions with security checks in the provided code snippets and consider whether they are dangerous functions or related to dangerous functions;
                6. The code snippets provided are often incomplete. If there are custom functions with unknown function bodies, please analyze the additional context information they need by yourself;
                7. Please analyze the code snippets provided from various angles of vulnerability analysis as much as possible, and be generous and thorough when identifying dangerous functions and other related functions, because you will analyze more code in subsequent steps;
                8. Please do not output irrelevant function names to the results and do not output a list of dangerous functions that is too long (for example, more than 10 elements), otherwise it will affect our next judgment.
                9. Please make sure that the output json is a legal json file and output your analysis process.        
            """,
    input_variables=["slice_lang","slice_vul","ocr_result","format_instructions"]
)



SystemPrompt = PromptTemplate(
    template="""You are a world-leading expert in vulnerability analysis, famous for discovering vulnerabilities in code snippets. You understand and are familiar with various languages including but not limited to decompiled pseudocode, C, C++, java, python, go, js, and you can read English and Chinese. Your task is to perform a detailed static code analysis, focusing on the following types of vulnerabilities:
                1. Arbitrary File Access (Arbitrary_file_access)
                2. Authentication Bypass (Authentication_bypass)
                3. Buffer Overflow (Buffer_overflow)
                4. Command Injection (Command_injection)
                5. Integer Overflow (Integer_overflow)
                6. Others (others): including but not limited to SQL injection, deserialization vulnerabilities, SSRF, XSS, UAF, conditional competition, format string and other types of vulnerabilities.
            """
)

#output
response_schemas_step1 = [
    ResponseSchema(name="vul_functions", description="a list of all dangerous functions", type="list[str]"),
    ResponseSchema(name="related_functions", description="a list of all related functions", type="list[str]")
]


length_limit=14000

"""
Connect to the OpenAI API and return the response
"""

# chat_template = ChatPromptTemplate.from_messages(
#     [
#         ("system", "You are a cyber security engineer whose job is to look at vulnerability disclosure websites and compile vulnerability information."),
#         ("human", "Hello, how are you doing?"),
#         ("ai", "I'm doing well, thanks!"),
#         ("human", "{user_input}"),
#     ]
# )
# create SystemMessagePromptTemplate

vul_list = ["Arbitrary_file_access", "Authentication_bypass", "Buffer_overflow", "Command_injection", "Integer_overflow", "others"]
SystemMessagePrompt = SystemMessagePromptTemplate(prompt=SystemPrompt)


def llm_api_step1(prompt, slice_lang, slice_vul):
    global length_limit
    if len(prompt)>length_limit:
        prompt = prompt[:length_limit]
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
    HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPromptStep1)
    # conbine Prompt
    chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas_step1)

    format_instructions = output_parser.get_format_instructions()

    chain=LLMChain(llm=llm, prompt=chat_template)
    try:
        output = chain.run(slice_lang=slice_lang,slice_vul=slice_vul,ocr_result=prompt,format_instructions=format_instructions)
        #print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        # Change later
        for i in range(10):
            # 先考虑输出只有危险函数的情况，其他相关函数（如调用链）不管
            if json_out["vul_functions"]:
                break
            output = chain.run(slice_lang=slice_lang,slice_vul=slice_vul,ocr_result=prompt,format_instructions=format_instructions)
            #print(output)
            json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        if check_output_regex(str(e)) == 1:
            length_limit = length_limit - 2000
        return None
    
def split_files(subdir_path, ext):
    functions=None
    if ext=='.c' or ext=='.h' or ext=='.cc' or ext=='.cpp':
        functions=process_c_files(subdir_path)
    elif ext=='.py':
        functions=process_python(subdir_path)
    elif ext=='.ts':
        functions=None
    elif ext=='.js':
        functions=split_jsp_files()
    elif ext=='.java':
        functions=process_java_files(subdir_path)
    elif ext=='.php':
        functions=process_php_files_in_directory(subdir_path)
    elif ext=='.go':
        functions=extract_functions_with_receivers(subdir_path)
    return functions

def run_step1_considering_timeout(file_content, slice_lang, slice_vul):
    global length_limit
    length_limit = 14000
    json_out_step1 = llm_api_step1(file_content, slice_lang=slice_lang, slice_vul=slice_vul)
    for i in range(50):
        if json_out_step1 is not None:
            break
        json_out_step1 = llm_api_step1(file_content, slice_lang=slice_lang, slice_vul=slice_vul)
    return json_out_step1
    

writed_result=0
def check_and_write(file_path,target1,target2,highest_score,second_highest,total_file_content):
    global writed_result
    try:
        if writed_result<=4:
            with open(file_path, 'a') as f:
                f.write(target1+'\n')
                writed_result+=1
                if highest_score < second_highest*2:
                    f.write(target2+'\n')
                    writed_result+=1
    except:
        pass

def run_step2(slice_vul,file_content, total_file_content):
    json_out_step2=None
    if slice_vul=="Arbitrary_file_access":
        json_out_step2 = check_arbitrary(file_content, key_env, base_env)
    elif slice_vul=="Authentication_bypass":
        json_out_step2 = check_bypass(file_content, key_env, base_env)
    elif slice_vul=="Buffer_overflow":
        json_out_step2 = check_bof(file_content, key_env, base_env)
    elif slice_vul=="Command_injection":
        json_out_step2 = check_command(file_content, key_env, base_env)
    elif slice_vul=="Integer_overflow":
        json_out_step2 = check_int_overflow(file_content, key_env, base_env)
    else:
        json_out_step2 = check_others(file_content, key_env, base_env)
    if not json_out_step2:
        return#not implemented yet
    print(json_out_step2)
    highest_score=0
    second_highest=0
    target1=None
    target2=None
    for item in json_out_step2['functions']:
        if item['confidence']>highest_score:
            target1=item['name']
            highest_score=item['confidence']
        elif item['confidence']>second_highest:
            target2=item['name']
            second_highest=item['confidence']
    #if highest_score < second_highest*2:
    #    print("prepare writing",target1,target2)
    #else:
    #    print("prepare writing",target1)
    a_dir = os.path.join(answer_dir, slice_vul)
    file_path = os.path.join(a_dir, 'answer.txt')
    if not os.path.exists(a_dir):
        os.makedirs(a_dir)
    check_and_write(file_path,target1,target2,highest_score,second_highest,total_file_content)

def step_by_step(type, subdir_path, answer_dir):
    global writed_result
    writed_result=0
    #split 返回content, slice_lang and slice_vul
    # Main function call
    #directory_path = '0'  # Replace with the actual directory path
    #process_directory(directory_path)
    #exit()

    # all type:
    #  .bz2, .c, .cc, .cfg, .crt, .csv, .go, .gz, .h, .html, .java, .jsp, .key, .php, .po, .py, .pyi, .ts, .txt, .xml
    # 黑名单文件的后缀名
    extensions = [".pyi",".bz2",".cfg",".crt",".csv",".gz",".html",".key",".po",'.txt','.xml']

    ext=None
    file_num=0
    for filename in os.listdir(subdir_path):
        file_path = os.path.join(subdir_path, filename)
        # 确保是文件而不是子目录
        if os.path.isfile(file_path):
            # 获取文件的扩展名（后缀名）
            ext = os.path.splitext(filename)[1].lower()
            if ext in extensions:
                continue
            file_num+=1
            if file_num>1:
                break
            with open(file_path, encoding='utf-8') as file:
                file_content = file.read()

    if file_num>1 or len(file_content)>10000:#split
        functions=None
        
    slice_vul = type
    #if slice_vul!="Arbitrary_file_access" and slice_vul!="Buffer_overflow":
    #    return
    
    slice_lang = ext[1:]
    if ext=='.c' or ext=='.h':
        slice_lang = "decompiled pseudocode or c programming language"
    elif ext=='.cc' or ext=='.cpp':
        slice_lang = "c++"
    elif ext=='.py':
        slice_lang = "python"
    elif ext=='.ts':
        slice_lang = "TypeScript"
    elif ext=='.jsp':
        slice_lang = "JavaScript"
    print(slice_lang,slice_vul)
    if file_num<=1 and len(file_content)<=14000:
        #edit, simply run step2
        run_step2(slice_vul,file_content,file_content)
        #json_out_step1 = run_step1_considering_timeout(file_content, slice_lang=slice_lang, slice_vul=slice_vul)
    else:
        #split
        if functions==None:
            return
        total=""
        for function in functions:
            total+=function
        file_content=""
        dangerous_funcs=[]
        related_funcs=[]
        if slice_vul=="Buffer_overflow" or slice_vul=="Integer_overflow" or slice_vul=="Command_injection" or slice_vul=="others":
            for function in functions:
                if len(file_content)+len(function)<=14000:
                    file_content+=function
                else:
                    run_step2(slice_vul,file_content,total)
                    file_content=function
            run_step2(slice_vul,file_content,total)
            return
        for function in functions:
            if len(file_content)+len(function)<=14000:
                file_content+=function
            else:
                json_out_step1 = run_step1_considering_timeout(file_content, slice_lang=slice_lang, slice_vul=slice_vul)
                dangerous_funcs+=json_out_step1["vul_functions"]
                try:
                    related_funcs+=json_out_step1["related_functions"]
                except:
                    pass
                file_content=function
        json_out_step1 = run_step1_considering_timeout(file_content, slice_lang=slice_lang, slice_vul=slice_vul)
        dangerous_funcs+=json_out_step1["vul_functions"]
        try:
            related_funcs+=json_out_step1["related_functions"]
        except:
            pass
        #print(dangerous_funcs)
        #print(related_funcs)
        file_content2=""
        analysed_funcs=[]
        for function in functions:
            try:
                head=function.split('\n')[0]+function.split('\n')[1]+function.split('\n')[2]  
            except:
                head=function
            for danger in dangerous_funcs:
                if danger in analysed_funcs:
                    continue
                if danger in head:
                    if len(file_content2)+len(function)>14000:
                        print("full")
                        run_step2(slice_vul,file_content2,total)
                        file_content2=function
                    file_content2+=function
                    analysed_funcs.append(danger)
        print(len(file_content2))

        if len(file_content2)<13000:#still have space
            for function in functions:
                try:
                    head=function.split('\n')[0]+function.split('\n')[1]+function.split('\n')[2]  
                except:
                    head=function
                for danger in related_funcs:
                    if danger in analysed_funcs:
                        continue
                    if danger in head:
                        if len(file_content2)+len(function)>14000:
                            print("full")
                            continue
                        file_content2+=function
                        analysed_funcs.append(danger)
        print(len(file_content2))
        run_step2(slice_vul,file_content2,total)
    
def search_data_dir(data_dir, answer_dir):
    # 当前目录下的数据集路径
    root_dir = data_dir
    answer_dir=answer_dir
    # 获取第一层所有目录名称
    top_level_dirs = []

    # 用于存储所有二级目录和对应的文件数量
    subdirs_with_file_count = []

    
    # 遍历每一个第一层目录
    for type in top_level_dirs:
        print(f"Processing directory: {type}")
        
        # 获取每个第一层目录的路径
        subdir_path = os.path.join(root_dir, type)
        
        # 遍历每个二级目录（数字目录如0, 1, 2）并统计文件数量
        for i in os.listdir(subdir_path):
            sub_dir = os.path.join(subdir_path, i)
            if os.path.isdir(sub_dir):
                total_size = sum(
                    os.path.getsize(os.path.join(sub_dir, f)) for f in os.listdir(sub_dir) 
                    if os.path.isfile(os.path.join(sub_dir, f))
                )
                # 将二级目录及其总文件大小保存到列表中
                subdirs_with_file_count.append((type, i, total_size))
                # 统计该二级目录下的文件数量
                #file_count = len([f for f in os.listdir(sub_dir) if os.path.isfile(os.path.join(sub_dir, f))])
                # 将二级目录及其文件数量保存到列表中
                #subdirs_with_file_count.append((type, i, file_count))

    # 根据文件数量排序（从小到大）
    subdirs_with_file_count.sort(key=lambda x: x[2])

    # 按照排序后的顺序输出文件内容
    for type, subdir, _ in subdirs_with_file_count:
        subdir_path = os.path.join(root_dir, type, subdir)
        print(f"\nEntering subdirectory: {subdir} in {type}")
        try:
            step_by_step(type,subdir_path,answer_dir)
        except Exception as e:
            print("analysing file error",e)
        # 遍历子目录中的文件
        #for filename in os.listdir(subdir_path):
            # file_path = os.path.join(subdir_path, filename)
            
            # # 确保是文件而不是子目录
            # if os.path.isfile(file_path):
            #     # 获取文件的扩展名（后缀名）
            #     ext = os.path.splitext(filename)[1].lower()
            #     if ext in extensions:
            #         continue
            #     # 打开并读取文件内容
            #     try:
            #         with open(file_path, encoding='utf-8') as file:
            #             file_content = file.read()
            #             step_by_step(type, ext, answer_dir, file_content)
            #     except Exception as e:
            #         print("analysing file error",e)
    #print(file_count)


if __name__ == '__main__':
    search_data_dir(data_dir, answer_dir)
    
