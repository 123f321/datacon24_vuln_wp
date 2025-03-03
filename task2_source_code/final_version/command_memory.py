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
import re
from langchain.memory import ConversationSummaryMemory 

SystemPrompt = PromptTemplate(
    template="You are a cybersecurity engineer, and your task is to analyze the provided code snippet and the potential vulnerability types to identify the function in the given code where the vulnerability is most likely to occur.",
)


HumanPromptStep2 = PromptTemplate(
    template=""" 
                User question: We will first provide several examples starting with ###Examples###, each of which contains a command injection vulnerability, and you need to summarize why they are considered vulnerable.
                The Chinese explanations and function names in the examples are very important, and do not miss any information when summarizing.
                Our previous conversation history will be saved in {history}.
                Finally, if we give you some content starting with the symbol ###New Content###, we are giving you several new functions that may contain similar command injection vulnerabilities.
                In this case, you should analyze each function independently and output the most vulnerable function. You should first repeat the previous historical information verbatim, and then use confidence (0-100) to measure the vulnerability of each function. Only one function should have the highest confidence.
                If the new content mentioned a function who have exactly the same name with one example function,that example function should have the highest confidence, and confidence of all other functions should be 0.
                If all functions in ###New Content### do not have vulnerabilities, their confidence should be 0.

                The content to be used is in <content>, which is either an example (just a summary) or new content (need to output the confidence and previous history of each function), and will not contain both types

                <context>

                {code_context}

                </context>

                Output format: a legal json file, such as {{"functions": [{{"name": "checkLoginUser","confidence": 0}},{{"name": "aaa","confidence": 10}}],"summary":"contains strcpy"}} and some additional information, such as previous history.
            """,
    input_variables=["code_context"]
)
"""
	User question:Please analyze the provided specific code of a series of functions to determine if any of these functions contain potential Command injection vulnerabilities ,Your analysis must consider:
	User Input Flow: Analyze how user input flows into command execution functions like system(). Look for cases where input affects the commands being executed.
	Sanitization: Check if user input is validated for malicious patterns like ;, &&, ||, |, $(), backticks, or other special characters.
	Let's analyze each function step by step based on the code I provide. We will consider each function independently and, based on the analysis criteria I give, assign a confidence score (confidence score:s 1~10) to each function:
        1.Determine the Use of Command Execution Functions like system(), exec(), popen(), Runtime.exec(), ProcessBuilder, etc. If such functions are present, add 10 points to the confidence level.
        2.Unvalidated User Input: if user input directly influences command execution without validation, add 20 points to the confidence level.
        3.Consider Permission operations: if giving function exists any operation on Permission like $permission, which may influnecethe the command injection function Input, add 20 points to the confidence level.
        4.Use of Shell Metacharacters: Direct concatenation allows inclusion of shell metacharacters in inputs, add 20 points to the confidence level.
        5.If the function contains strings related to RCE such as "smb" or "/bin/sh", add 30 extra points to the confidence score. 
	
        <context>
        {code_context}
        </context>
        answer user's question with the information in <context>
        output format: {format_instructions}
        an example of output is:curly_brace"functions": [curly_brace "name": "daemonCheck","confidence": 10 end_curly_brace,curly_brace "name": "daemonControl","confidence": 30 end_curly_brace] end_curly_brace
"""

examples="""
Example 1: 在 daemonControl()中存在命令注入:
public function daemonControl($daemon_name, $command) {
    global $user;
    if ($command == 'check' || $command == 'status') {
      $permission = 'View';
    } else {
      $permission = 'Edit';
    }
    $allowed = (!$user) || ($user['System'] == $permission );
    if ( !$allowed ) {
      throw new UnauthorizedException(__("Insufficient privileges"));
      return;
    }
    $string = ZM_PATH_BIN."/zmdc.pl $command $daemon_name";
    $result = exec($string); # 这里缺乏验证
    $this->set(array(
      'result' => $result,
      '_serialize' => array('result')
    ));
}

Example 2: 这是CVE-2020-16846中的一个命令注入漏洞, 出现的脚本位于salt/salt/client/ssh/shell.py:
def gen_key(path):
    '''
    Generate a key for use with salt-ssh
    '''
    cmd = 'ssh-keygen -P "" -f {0} -t rsa -q'.format(path)
    if not os.path.isdir(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
    subprocess.call(cmd, shell=True)
1. `subprocess.call(cmd, shell=True)` 允许攻击者通过 `path` 参数注入恶意命令。
2. 通过构造特殊的 `path` 值来执行任意命令。

Example 3: 在sub_40749C函数中:
ChildNodeByName = ATP_XML_GetChildNodeByName(*(_DWORD *)(a1 + 44), "NewDownloadURL", 0, &v4);
if ( !ChildNodeByName )
{
  if ( v4 )
  {
    ChildNodeByName = ATP_XML_GetChildNodeByName(*(_DWORD *)(a1 + 44), "NewStatusURL", 0, &v5);
    if ( !ChildNodeByName )
    {
      if ( v5 )
      {
        snprintf(v6, 1024, "upg -g -U %s -t '1 Firmware Upgrade Image' -c upnp -r %s -d -b", v4);
        system(v6);
      }
这一段函数会将 v4 中的代码拼到 v6 中并执行 system 函数，存在命令注入。

Example 4: sub_442260中的apt_get接受了来自sub_441CF0中apt_set存储的数据, 并将其拼接进命令执行语句中：
if ( apmib_get(7026, v37) )
    {
      snprintf(v40, 6, "ping  ");
      v3 = strlen(v37);
      strncat(v40, v37, v3);
    ....
    system(v40);

Example 5: ConstDef对象的constDefine成员变量会被传给ConstDefManagerImpl#eval求值, 造成任意代码执行:
private Object eval(String scriptText, Map<String, Object> context) throws ScriptException {
        Object o = this.cache.get(scriptText);
        CompiledScriptRunner runner = null;
        if (o != null) {
            runner = (CompiledScriptRunner)o;
        } else {
            runner = new CompiledScriptRunner(this.groovyEngine, scriptText);
            this.cache.put(scriptText, runner);
        }

        long start = System.currentTimeMillis();
        Object result = runner.eval(context);
        long l = System.currentTimeMillis() - start;

        return result;
    }

Example 6: 在sub_46C59C函数中:
sscanf(local_c,"%[^;];%s",local_68,local_a8);
    if ((local_68[0] == '\0') || (local_a8[0] == '\0')) {
      printf("[%s():%d] luaFile or configFile len error.\n","tddp_cmd_configSet",0x22b);
    }
    else {
      local_18 = inet_ntoa((in_addr)*(in_addr_t *)(param_1 + 4));
      FUN_000091dc("cd /tmp;tftp -gr %s %s &",local_68,local_18);

  vsprintf((char *)apcStack_11c,param_1,&uStack_c);
  printf("[%s():%d] cmd: %s \r\n","tddp_execCmd",0x48,apcStack_11c);
  local_1c = fork();
  if (-1 < local_1c) {
    if (local_1c == 0) {
      local_130[0] = (char **)&DAT_00016f48;
      local_130[1] = (char **)&DAT_00016f4c;
      local_130[2] = apcStack_11c;
      local_130[3] = (char **)0x0;
      execve("/bin/sh",(char **)local_130,(char **)0x0);
                    /* WARNING: Subroutine does not return */
      exit(0x7f);
    }
sscanf函数将传进来的TDDP包数据区按照分离符;分为两个字符串，其中利用“正则表达式”过滤;之后字符串拼接到了cd /tmp;tftp -gr的后面, 最后在函数FUN_000091dc有个命令执行处。
  
Example 7:在FUN_0041af68函数中:
  int iVar1;
  char *pcVar2;
  undefined4 uVar3;
  int local_48;
  char acStack_3c [52];
  
  iVar1 = FUN_00410e4c();
  if (iVar1 == 0) {
    uVar3 = uci_safe_get("usbapps.config.smb_admin_name");
    _system("deluser %s",uVar3);
    for (local_48 = 0; local_48 < 0x19; local_48 = local_48 + 1) {
      sprintf(acStack_3c,"usbapps.@smb[%d].username",local_48);
      iVar1 = uci_safe_get(acStack_3c);
      if (iVar1 == 0) break;
      _system("smbpasswd -x %s",iVar1);
uci_safe_get为用户可控输入, 传入到_system函数处造成命令执行。
"""

response_schemas_step2 = [
    ResponseSchema(name="functions", description="a list of function names with their respective confidence levels"),
    ResponseSchema(name="summary", description="the summary of your judging reason")
]
memory=None

length_limit=14000

def check_output_regex(output):
    pattern = r"maximum context length is 8000 tokens"
    if re.search(pattern, output):
        return 1
    else:
        return 0
    
def llm_api_step2(prompt_code, key_env, base_env):
    global memory
    global length_limit
    if len(prompt_code)>length_limit:
        prompt_code = prompt_code[:length_limit]
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
    if memory==None:
        memory = ConversationSummaryMemory(llm=llm)
    # create HumanMessagePromptTemplate
    HumanMessagePrompt = HumanMessagePromptTemplate(prompt=HumanPromptStep2)
    SystemMessagePrompt = SystemMessagePromptTemplate(prompt=SystemPrompt)
    # conbine Prompt
    chat_template = ChatPromptTemplate.from_messages([SystemMessagePrompt,HumanMessagePrompt])

    output_parser = StructuredOutputParser.from_response_schemas(response_schemas_step2)

    format_instructions = output_parser.get_format_instructions()
    #prompt = split_prompt(prompt, 6000)

    chain=LLMChain(llm=llm, prompt=chat_template, memory=memory)
    try:
        output = chain.run(code_context=prompt_code)
        #print(output)
        json_out=output_parser.parse(output)
        # AI may regard a content to be None not NULL
        # Change later
        for i in range(10):
            if json_out["functions"] or json_out["functions"]==[]:
                break
            output = chain.run(code_context=prompt_code)
            #print(output)
            json_out=output_parser.parse(output)
        return json_out
    except Exception as e:
        print(f"Request timed out. {e}")
        if check_output_regex(str(e)) == 1:
            length_limit = length_limit - 2000
        return None
    
def check_command(prompt_code, key_env, base_env):
    global length_limit
    global memory
    memory = None
    length_limit = 14000
    sample=examples
    json_out=llm_api_step2("###Examples###"+sample, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2("###Examples###"+sample, key_env, base_env)
    json_out=llm_api_step2("###New Content###"+prompt_code, key_env, base_env)
    for i in range(50):
        if json_out is not None:
            break
        json_out=llm_api_step2("###New Content###"+prompt_code, key_env, base_env)
    return json_out

# check by yourself
#filepath='a'
#with open(file_path, encoding='utf-8') as file:
#    file_content = file.read()
#json_out=check_arbitrary(file_content, "8bb73128d0b5732a1e0723f922245df8", 'https://poc.qianxin.com')
