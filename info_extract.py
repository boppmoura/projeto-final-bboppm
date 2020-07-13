import pickle
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
from ghidra.program.model.lang.OperandType import SCALAR, REGISTER
from ghidra.program.model.symbol.RefType import READ, WRITE
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.address import Address

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.app.decompiler.component import DecompilerUtils



from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.lang import *
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
import argparse
import sys
import os
import json

listing = currentProgram.getListing()
ins_list = listing.getInstructions(True)

ghidra_default_dir = os.getcwd()


jython_dir = os.path.join(ghidra_default_dir, "Ghidra", "Features", "Python", "lib", "Lib", "site-packages")

sys.path.insert(0,jython_dir)


drop_list = ["ParentNamespace", "Tags", "StackFrame", "Class", 
        "SignatureSource", "AllVariables", "Symbol", "RepeatableCommentAsArray",
        "CommentAsArray", "Comment", "__ensure_finalizer__", "__str__",
        "__hash__",  "__unicode__", "hashCode", "__repr__", "ID",
        "FunctionThunkAddresses"]

param_attrs = ['name', 'size', 'length', 'memoryVariable',
        'ordinal', 'register', 'registerVariable', 'registers', 'stackOffset', 
        'stackVariable', 'firstUseOffset', 'forcedIndirect', 'formalDataType', 
        'dataType', 'variableStorage']

hiparam_attr = ['name', 'size', 'slot', 'storage', 'dataType']

var_attrs = ['name', 'dataType', 'firstUseOffset', 'registerVariable', 'length',
        'source', 'stackOffset', 'stackVariable', 'register', 'registers']

ret_attr = ['dataType', 'register', 'length', 'name']


ret_attr = ['dataType', 'register', 'length', 'name']


regList = ['EBP','EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'ESP']

sinks = ['putchar','strcpy','memcpy','gets', 'fgets','puts', 'memmove','scanf','lstrcpyA''strcpyA','strcpyW','wcscpy','_tcscpy','_mbscpy','StrCpy','StrCpyA','StrCpyW','lstrcpy','lstrcpyA''lstrcpyW', 
'_tccpy','_mbccpy','_ftcscpy','strncpy','wcsncpy','_tcsncpy','_mbsncpy','_mbsnbcpy','StrCpyN','StrCpyNA','StrCpyNW','StrNCpy','strcpynA','StrNCpyA','StrNCpyW', 'lstrcpyn','lstrcpynA','lstrcpynW', 'sprintf',  'snprintf']

sinks2 = ['strlen', 'strcspn','getdelim', 'getline', 'strlcpy', 'snprintf', 'memcpy_s', 'strcpy_s', 'strcat_s', 'sprintf_s', ' fscanf', 'cgets', 'getc', 'strcat']

listIni = ['A']


mneRule1 = ['CALL', 'JMP']

mneRule2 =['MOV', 'MOVS', 'MOVSX', 'MOVZX', 'MOVSB', 'MOVSW', 'MOVSD']

mneRule3 = ['TEST','CMP']
mneRule4 = ['JMP']
mneRule5 = ['CALL', 'JMP']

zzz = listIni

regras_ting = []



def get_param_info(param):
    ret_dict = {}

    for attr in param_attrs:
        try:
            value = getattr(param, attr)
            ret_dict[attr] = str(value)
        except AttributeError as e:
            pass
        except java.lang.UnsupportedOperationException as e:
            pass

    try:
        ret_dict['data_type'] = str(param.getDataType())
    except AttributeError as e:
        pass

    return ret_dict

def get_var_info(var):
    ret_dict = {}

    for attr in var_attrs:
        value = getattr(var, attr)
        ret_dict[attr] = str(value)

    return ret_dict

def get_ret_info(var):
    ret_dict = {}

    for attr in ret_attr:
        value = getattr(var, attr)
        ret_dict[attr] = str(value)

    return ret_dict


def make_pickleable(func_dict):

  
    
    for item in drop_list:
        func_dict.pop(item)

    params = []
    for parm in func_dict['Parameters']:
        param_dict = get_param_info(parm)
        params.append(param_dict)
    func_dict['Parameters'] = params

    vars_list = []
    for var in func_dict['LocalVariables']:
        var_dict = get_var_info(var)
        vars_list.append(var_dict)
    func_dict['LocalVariables'] = vars_list

    # EntryPoint
    EntryPoint = {
            'offset' : str(func_dict['EntryPoint'].offset),
            'physicalAddress' : str(func_dict['EntryPoint'].physicalAddress)
            }
    func_dict['EntryPoint'] = EntryPoint

    # Ret
    func_dict['Return'] = get_ret_info(func_dict['Return'])
    func_dict['ReturnType'] = str(func_dict['ReturnType'])

    # Program name
    func_dict['Program'] = str(func_dict['Program'].name)

    # Calling Function
    func_dict['CallingFunctions'] = func_dict['CallingFunctions'].toArray()
    calling_funcs = []
    for func in func_dict['CallingFunctions']:
        t_func = {}
        t_func['Name'] = str(func.name)
        t_func['Addr'] = str(func.entryPoint)
        calling_funcs.append(t_func)

    func_dict['CallingFunctions'] = calling_funcs

    # Body
    body = []
    for addrRange in func_dict['Body'].addressRanges:


        
        


        c = addrRange.minAddress 
        d = addrRange.maxAddress 


    
        ins = getInstructionAt(c)
        xxx =  "A"
     
        while xxx != "RET":
            xxx = (getInstructionAfter(ins).getMnemonicString())
            ins = getInstructionAfter(ins)

            reg0Regra1 = listIni
            reg1Regra1 = listIni
            reg0Regra2 = listIni
            reg1Regra2 = listIni
            reg0Regra3 = listIni
            reg1Regra3 = listIni
            reg0Regra31 = listIni
            reg1Regra31 = listIni
                          


            abc = str(ins)

            mnemonic = ins.getMnemonicString()

#------------------------------------------------------------Regra 2 mov  ptr[reg], XXX /// mov ptr [reg], reg------------------------------------------

            if mnemonic in mneRule2:

                ins1, ins2 = abc.split(',')
                
                #REGRA 2.1

                if 'word ptr [' in str(ins1):

                    
                    for x in ins.getOpObjects(0):
                      
                        if str(x) in regList:
                          
                            reg0Regra2 = x
                            break
                            
                    
                         
                           
                    for x in ins.getOpObjects(1):
                      
                        if str(x) in regList:  
                           
                            reg1Regra2 = x
                          
                            break


                   

                    if str(reg0Regra2) in regList and str(reg1Regra2) in regList:
                        
                        print ("regra 2 atingida", "instrucao", ins, "reg 1", reg0Regra2, "reg 2", reg1Regra2, "endereco",  getMinAddress(ins))
                        Regra2 = {'RegraTing': 2,  'instrucao' : str(ins), 'operando0' : str(reg0Regra2), 'operando1' : str(reg1Regra2), 'endereco' : str(getMinAddress(ins))}
                        regras_ting.append(Regra2)

                        with open('file.txt', 'a') as file:
                            file.write(json.dumps(Regra2)) 
                            file.write('\n')
                            Regra2 = {}
                      


                                         
                    if str(reg0Regra2) in regList and str(reg1Regra2) not in regList:
                      

                        
                        print ("regra 2.3 atingida", "instrucao", ins, "reg 1", reg0Regra2, getMinAddress(ins))


                        Regra23 = {'RegraTing': 23, 'instrucao' : str(ins), 'operando0' : str(reg0Regra2), 'operando1' : 'A', 'endereco' : str(getMinAddress(ins))}
                        regras_ting.append(Regra23)
                        with open('file.txt', 'a') as file:
                            file.write(json.dumps(Regra23)) 
                            file.write('\n')
                            Regra23 = {}
                     

                                            
 #-----------------------------REGRA 2 VIA MOV REG, REG-------------------------------------------------------------------------------------------                                   
                else:
                    
                    for x in ins.getOpObjects(0):
                       
                        if str(x) in regList:
                            reg0Regra2 = x
                            
                          
                            break
                            
                     
                    for x in ins.getOpObjects(1):
                      
                        if str(x) in regList:
                            reg1Regra2 = x
                        
                            break
                      
                    
                    if str(reg0Regra2) in regList and str(reg1Regra2) in regList:

                        print ("regra 2 atingida", "instrucao", ins, "reg 1", reg0Regra2, "reg 2", reg1Regra2, "endereco",  getMinAddress(ins))
                        Regra2 = {'RegraTing': 2, 'instrucao' : str(ins), 'operando0' : str(reg0Regra2), 'operando1' : str(reg1Regra2), 'endereco' : str(getMinAddress(ins))}
                        regras_ting.append(Regra2)
                        with open('file.txt', 'a') as file:
                            file.write(json.dumps(Regra2)) 
                            file.write('\n')
                            Regra2 = {}
                     
                        
             
#----------------------------REGRA 3  ----------------------------------------------

            if mnemonic in mneRule3:
               
                
                for x in ins.getOpObjects(0):
                  
                    if str(x) in regList:
                        reg0Regra31 = x
                       
                        continue
            

                for x in ins.getOpObjects(1):
                   
                    if str(x) in regList:
                        reg1Regra31 = x
                        
                        break
                        

                if str(reg0Regra31) in regList and str(reg1Regra31) in regList:
                   

                    print ("regra 3 atingida", "instrucao", ins, "reg 1", reg0Regra31, "reg 2", reg1Regra31, getMinAddress(ins))
                    Regra31 = {'RegraTing': 31, 'instrucao' : str(ins), 'operando0' : str(reg0Regra31), 'operando1' : str(reg1Regra31), 'endereco' : str(getMinAddress(ins))}
                    regras_ting.append(Regra31)
                    with open('file.txt', 'a') as file:
                            file.write(json.dumps(Regra31)) 
                            file.write('\n')
                            Regra31 = {}
                  

#----------------------------------------------------------------------------------------------
#----------------------------REGRA 4 -------------------------------------------------------------
#-----------------------------------------------------------------------------------------------
            if mnemonic in mneRule5: 

                
                ops = ins.getOpObjects(0)
                target_addr = ops[0]
                
                func_name = None 

                if isinstance(target_addr,Address):
                    code_unit = listing.getCodeUnitAt(target_addr) 
                 
                    if code_unit is not None:
                        ref = code_unit.getExternalReference(0) 
                        
                        if ref is not None:
                            func_name = ref.getLabel()
                           
                        else:
                            func = listing.getFunctionAt(target_addr)
                            
                            try:
                                func_name = func.getName()
                               
                            except:
                                pass
                    
                    if func_name in sinks2:
                        
                    
                        
                        x =  ins.fallFrom
                        z = getInstructionAt(x)
                   

                        
                        duplicate.append(func_name)
                       

                        for y in z.getOpObjects(0):
                           
                            if str(y) in regList:

                                reg0Regra4 = y
                              
                                break
                                
                        for y in z.getOpObjects(1):
                            
                            if str(y) in regList:
                                reg1Regra4 = y
                                break
                               
                        if str(reg0Regra4) in regList or str(reg1Regra4) in regList:
                           

                            print ("regra 4 atingida", "instrucao", z, "reg 1", reg0Regra3, "reg 2", reg1Regra3, "inst associada a regra 2", ins, "endereco",  getMinAddress(z), "syscall", str(func_name))
                            Regra4 = {'RegraTing': 4, 'instrucao' : str(z), 'operando0' : str(reg0Regra4), 'operando1' : str(reg1Regra4), 'endereco' : str(target_addr), 'instr_associada' : str(ins.getMinAddress()), 'syscall' : str(func_name)}
                            regras_ting.append(Regra4)
                            with open('file.txt', 'a') as file:
                                file.write(json.dumps(Regra4)) 
                                file.write('\n')
                                Regra4 = {}                                                                                   
                           

                           

                

            

#----------------------------------------Regra 1 (syscalls inseguras)  ----------------------------------------------
#--------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------
            if mnemonic in mneRule1:   
                try:
                    ops = ins.getOpObjects(0)
                    target_addr = ops[0]
                    #print ("esse eh o targt_addr", target_addr)
                    func_name = None 

                    if isinstance(target_addr,Address):
                        code_unit = listing.getCodeUnitAt(target_addr)
                       
                        if code_unit is not None:
                            ref = code_unit.getExternalReference(0) 
                            #print ("referencia externa",ref)
                            if ref is not None:
                                func_name = ref.getLabel()
                                
                            else:
                                func = listing.getFunctionAt(target_addr)
                                
                                try:
                                    func_name = func.getName()
                                   
                                except:
                                    pass

                        
                        if func_name in sinks:
                            x =  ins.fallFrom
                            z = getInstructionAt(x)
                           
                            
                            duplicate.append(func_name)
                            
                            for y in z.getOpObjects(0):
                               
                                if str(y) in regList:
                                    reg0Regra1 = y
                               
                                    break
                                    
                            for y in z.getOpObjects(1):
                                
                                if str(y) in regList:
                                    reg1Regra1 = y
                               
                                    break
                               

                            if str(reg0Regra1) in regList or str(reg1Regra1) in regList:
                                
                               

                                print ("regra 1 atingida", "instrucao", z, "reg 1", reg0Regra1, "reg 2", reg1Regra1, "inst associada a regra 2", ins, "endereco",  getMinAddress(z), "syscall", str(func_name))
                                Regra1 = {'RegraTing': 1, 'instrucao' : str(z), 'operando0' : str(reg0Regra1), 'operando1' : str(reg1Regra1), 'endereco' : str(target_addr), 'instr_associada' : str(ins.getMinAddress()), 'syscall' : str(func_name)}
                                regras_ting.append(Regra1)
                                with open('file.txt', 'a') as file:
                                    file.write(json.dumps(Regra1)) 
                                    file.write('\n')
                                    Regra1 = {}                                                                                     #
                except:
                    pass


                                   



    func_dict['Regras'] = regras_ting
 

    body.append((str(addrRange.minAddress), str(addrRange.maxAddress)))

    func_dict['Body'] = body 

    func_dict['CallingConvention'] = str(func_dict['CallingConvention'])
    func_dict['Signature'] = str(func_dict['Signature'])

    return func_dict

#/////////////////////////////////////////////////////////////////////////////////////////
#/////////////////////////////////////////////////////////////////////////////////////////

from ghidra.program.model.address.Address import *
from ghidra.program.model.listing.CodeUnit import *
from ghidra.program.model.listing import *
from ghidra.program.model.lang.OperandType import SCALAR, REGISTER
from ghidra.program.model.symbol.RefType import READ, WRITE
from ghidra.program.model.symbol.SourceType import *
from ghidra.program.model.address import *


flatapi = ghidra.program.flatapi.FlatProgramAPI(getCurrentProgram(), getMonitor())
decapi = ghidra.app.decompiler.flatapi.FlatDecompilerAPI(flatapi)
decapi.initialize()
ghidra.program.model.listing
decInt = decapi.getDecompiler()



sink_dic = {}
duplicate = []


listing = currentProgram.getListing()
ins_list = listing.getInstructions(True)

refmanager = currentProgram.referenceManager
endbase = currentProgram.getImageBase()

#print ("endereco base", endbase)
blockiterator = BasicBlockModel(currentProgram).getCodeBlocks(monitor)

func_list = []
function = getFirstFunction()
while function is not None:
    


    func_dict = {}

    for x in dir(function):
        try:
            method = getattr(function,x)
            func_dict[x.replace('get','')] = method()
        except:
            pass
    func_dict['CallingFunctions'] = function.getCallingFunctions(getMonitor())
    func_dict['ProtoTypeString'] = function.getPrototypeString(True,True)

    
    DecRes = decInt.decompileFunction(function, 120, getMonitor())
    DecFunc = DecRes.getDecompiledFunction()

    Top_Prototype = str(DecFunc.getSignature())
    if True:
        c_code = DecFunc.getC()
        func_dict['c_code'] =  c_code

    HiFunc = DecRes.getHighFunction()
    HiFuncProto = HiFunc.getFunctionPrototype()
    HiFuncParamCount = HiFuncProto.getNumParams()

    HiFuncParams = []
    HiRetType = HiFuncProto.getReturnType()
    for x in range(HiFuncParamCount):
        parm = HiFuncProto.getParam(x)
        temp_parm = {}
        for attr in hiparam_attr:
            value = getattr(parm,attr)
            temp_parm[attr] = str(value)
        HiFuncParams.append(temp_parm)

    func_dict['HiParameters'] = HiFuncParams
    func_dict['HiParameterCount'] = HiFuncParamCount
    func_dict['HiRetType'] = str(HiRetType)
    func_dict['HiFuncProto'] = Top_Prototype
    k =  str(func_dict['Program'])

    
        
    func_dict = make_pickleable(func_dict)
   
    func_list.append(func_dict)

    function = getFunctionAfter(function)


parser = argparse.ArgumentParser()

parser.add_argument("Output", help="Localização do pickle file")
parser.add_argument("--func_addr", required=False)
parser.add_argument("--func_name", required=False)


try:
    input_args = getScriptArgs()
except NameError as e:
    print("Só pode ser rodado no modo headless")
    exit(0)

if  len(input_args) > 0:
    input_args = input_args[0]
    if len(input_args.split()) > 1:
        input_args = shlex.split(input_args)
    else:
        input_args = [input_args]
else:
    input_args = ""

args = parser.parse_args(input_args)

with open(args.Output, 'wb') as f:
    pickle.dump(func_list,f,-1)

print("[+] Dump de dados concluído")

with open('fileTing', 'wb') as f:
    pickle.dump(regras_ting,f,-1)



x = 'FIM DO PROGRAMA ===================================================================================='
y = '===================================================================================================='

with open('file.txt', 'a') as file:
    file.write(json.dumps(x)) #
    file.write('\n')
    file.write(json.dumps(y)) #
    file.write('\n')
    file.write(json.dumps(k)) #
    file.write('\n')
    file.write(json.dumps(y)) # 
    file.write('\n')
    

