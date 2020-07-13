import angr
from angr import sim_options as so
import os
import pickle
import claripy
import argparse
import r2pipe
import string
from multiprocessing import Process, Queue
from _PF_Limited_Process import Limited_Process
import psutil
import IPython
from termcolor import colored
import time
import json




import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

file_name = None
limited_processes = []

full_output_path = '/home/bboppm/ghidra/ghidra_9.1_PUBLIC/support/saida-TC'
regras_ting = '/home/bboppm/ghidra/ghidra_9.1_PUBLIC/support/fileTing'



functions = []

def main():  

    parser = argparse.ArgumentParser()

    parser.add_argument("FILE")

    args = parser.parse_args()

    print("[+] Getting argument functions")
    arg_funcs = get_arg_funcs(full_output_path) 

    func_list = list(arg_funcs) 
    


    
    
    lista_regras_filtered=[]

    list_regras = []
    with open(regras_ting, 'rb') as f:
        list_regras = pickle.load(f)


    print ("==========================================================INICIO DO PROGRAMA ANALISADO")

    tingidos=[]
    tingidos1=[]
    tingidos2=[]
    func_iter = 0
    func_timeout = 200
    list_regrasTingidas={}
    list_regrasTingidas1={}
    list_regrasTingidas2={}

    while len(func_list) > 0 and func_iter < len(func_list):
        
        m_data = (func_list[func_iter])  #SAIDA DO DUMPFUNCTIONS.PY DIVIDIDA POR FUNCAO

        print("Starting {}".format(func_list[func_iter]['name']))
     
        nome = trace_function(m_data, list_regras)
     
        if list_regrasTingidas != False:
            tingidos.append(list_regrasTingidas)

        if list_regrasTingidas1 != False:
            tingidos1.append(list_regrasTingidas1)
        if list_regrasTingidas2 != False:
            tingidos2.append(list_regrasTingidas2)

 
    y = '===================================================================================================='
    x = 'FIM DO PROGRAMA====================================================================================='
    with open('visaoFinal.txt', 'a') as file:
        file.write(json.dumps(x)) 
        file.write('\n')
        file.write(json.dumps(nome)) 
        file.write('\n')
        file.write(y)
        file.write('\n')




   

def get_arg_funcs(file_name, useHiFunc=True): 

    return [x for x in get_function_information(file_name) if len(x) > 0]
    

def trace_function(func, list_regras, ld_path=""):
    start_addr = func['offset']
    file_name = func['Program'] 


    args = get_func_args(func) 
    regElse = ['1', '12', '21', '24', '3', '22', '25', '11']
    regETing1 = ['23', '4']
    regETing2 = ['31', '2']

    my_extras = {
        so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,
        so.TRACK_MEMORY_ACTIONS, so.ACTION_DEPS
    }
    
    regras = {}
    regras1 = {}
    regras2 = {}

    
    base_addr = get_base_addr(file_name)
    print ("endereco base: ", base_addr)

    with open('visaoFinal.txt', 'a') as file:
        file.write(json.dumps(base_addr)) 
        file.write('\n')

     
    my_extra = angr.options.resilience.union(my_extras)
    p = angr.Project(file_name,         
                     main_opts={'base_addr': base_addr},load_options={'auto_load_libs': False})
    
    arg_types = []
    for x in args:
        if x is not None and 'type' in x.keys():
            x = x['type']
            if x is not None: 
                try:
                    arg_types.append(angr.sim_type.parse_type(x))
                except:
                    if "*" in x:
                        x = "byte *"
                    else:
                        x = "int"
                    arg_types.append(angr.sim_type.parse_type(x))

   
    clarip_vars = []
    for arg in arg_types:
       
        temp_arg = claripy.BVS(arg.name, arg.with_arch(p.arch).size) #--<BV32 int_1_32> <BV32 int_2_32>, 
        
        clarip_vars.append(temp_arg)
      

    args_dict = zip(args, arg_types, clarip_vars)
    state = p.factory.call_state(start_addr,*clarip_vars,add_options=my_extra)  

    state.globals['exploitable'] = False
    state.globals['args'] = args_dict
    simgr = p.factory.simgr(state, save_unconstrained=True) 

    simgr.active
   
    while len(simgr.active) == 1:


        for path in simgr.active:


            

            y = str(path)

            h = y.replace("<SimState @ 0x", "")
            j = h.replace(">", "")

                     
           
            for x in list_regras:
               

                if j in str(x['endereco']) and j != str(0):

                    if str(x['RegraTing']) not in regElse:
                       


                    

                        reg1tingido = False
                        reg2tingido = False

                                          
                        

                        if path.satisfiable(extra_constraints=[path.regs.eax == b"AAAA"]):
                            path.add_constraints(path.regs.eax == b"AAAA")

                            regtingido = 'EAX'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                                
                            if regtingido == x['operando1']:
                                reg2tingido = True
                                
                           

                        if path.satisfiable(extra_constraints=[path.regs.ebx == b"AAAA"]):
                            path.add_constraints(path.regs.ebx == b"AAAA")
                            regtingido = 'EBX'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                               
                            if regtingido == x['operando1']:
                                reg2tingido = True
                               

                        if path.satisfiable(extra_constraints=[path.regs.ecx == b"AAAA"]):
                            path.add_constraints(path.regs.ecx == b"AAAA")
                            regtingido = 'ECX'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                               
                            if regtingido == x['operando1']:
                                reg2tingido = True
                                

                        if path.satisfiable(extra_constraints=[path.regs.edx == b"AAAA"]):
                            path.add_constraints(path.regs.edx == b"AAAA")

                            regtingido = 'EDX'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                               
                            if regtingido == x['operando1']:
                                reg2tingido = True
                               
                            
                        if path.satisfiable(extra_constraints=[path.regs.esi == b"AAAA"]):
                            path.add_constraints(path.regs.esi == b"AAAA")


                            regtingido = 'ESI'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                            
                            if regtingido == x['operando1']:
                                reg2tingido = True
                            
                           
                        if path.satisfiable(extra_constraints=[path.regs.edi == b"AAAA"]):
                            path.add_constraints(path.regs.edi == b"AAAA")

                            regtingido = 'EDI'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                           
                            if regtingido == x['operando1']:
                                reg2tingido = True
                           

                        if path.satisfiable(extra_constraints=[path.regs.ebp == b"AAAA"]):
                            path.add_constraints(path.regs.ebp == b"AAAA")

                            regtingido = 'EBP'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                                
                            if regtingido == x['operando1']:
                                reg2tingido = True
                                
                        if path.satisfiable(extra_constraints=[path.regs.esp == b"AAAA"]):
                            path.add_constraints(path.regs.esp == b"AAAA")


                            regtingido = 'ESP'

                            if regtingido == x['operando0']:
                                reg1tingido = True
                               
                            if regtingido == x['operando1']:
                                reg2tingido = True
                           
                        

                       

#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

                        if str(x['RegraTing']) in regETing1:                        


                            if reg1tingido == True or reg2tingido == True:
                                
                                regras = x
                              
                               
                                with open('visaoFinal.txt', 'a') as file:
                                    file.write(json.dumps(x))
                                    file.write('\n')


                        if str(x['RegraTing']) in regETing2:                        


                            if reg1tingido == True and reg2tingido == True:
                                

                                regras2 = x
                             
                                
                                with open('visaoFinal.txt', 'a') as file:
                                    file.write(json.dumps(x))
                                    file.write('\n')


                   



                    if str(x['RegraTing']) in regElse:

                        

                        regras1 = x
                      
                        
                        with open('visaoFinal.txt', 'a') as file:
                            file.write(json.dumps(x)) 
                            file.write('\n') 

                  




        simgr.step()

        if len(simgr.unconstrained):
            
            
            for path in simgr.unconstrained:
                if path.satisfiable(extra_constraints=[path.regs.pc == b"AAAA"]):
                    if check_actions(path):
                        path.add_constraints(path.regs.pc == b"AAAA")
                        if path.satisfiable():
                            
                            
                            with open('visaoFinal.txt', 'a') as file:
                                file.write(json.dumps(str(path)))
                                file.write('\n') 

            

   

  




    return file_name




   

def check_actions(path):
    for action in path.history.actions:
        if isinstance(action, angr.state_plugins.sim_action.SimActionData) and action.actual_value is not None:
            action_value = path.solver.eval(action.actual_value, cast_to=bytes, extra_constraints=[path.regs.pc == b"AAAA"])
            if action_value == b"AAAA":
                continue
                #return True
            if len(action_value) > 4:
                return True



def get_function_information(file_name):
    

    if os.path.exists(file_name):
        functions = load_functions_from_file(file_name)
        
       
    else:
        print(
            "Não foi possível obter informações da função {}".format(file_name))

   # shutil.rmtree(dirpath)

    functions = [r2_compatible(x) for x in functions]
    

    return functions


def r2_compatible(func): 

    func['name'] = func['Name']
    func['offset'] = int(func['EntryPoint']['offset'])

    return func



def load_functions_from_file(file_name):

    ret_list = []
    with open(file_name, 'rb') as f:
        ret_list = pickle.load(f)
    return ret_list

def get_func_args(func, useHiFunc=True):
    arg_list = []
    param_list = "Parameters"
    if useHiFunc:
        param_list = "HiParameters"

    for param in func[param_list]:
        param_type = param['dataType']
        param_type = fix_angr_data_type(param_type)
        param['type'] = param_type
        if 'storage' in param.keys():
            param['ref'] = param['storage']
        else:
            param['ref'] = param['variableStorage']
    return func[param_list]


def fix_angr_data_type(dataType): 
    if "undefined" in dataType:
        return "int"
    if "uint" in dataType:
        return dataType.replace("uint", "int")


def get_base_addr(file_name):
    r2_ins = r2pipe.open(file_name, flags=["-2"])
    return r2_ins.cmdj('ij')['bin']['baddr']


if __name__ == "__main__":
    main()



