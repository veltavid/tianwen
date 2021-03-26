from idc import *
import FIDL.decompiler_utils as du
from prettytable import PrettyTable


def get_para(func_name):
	if(func_name==".read"):
		buf_idx=1
		size_idx=2
	elif(func_name==".strcat"):
		buf_idx=0
		size_idx=-1
	elif(func_name==".sprintf"):
		buf_idx=0
		size_idx=-1
	elif(func_name==".strcpy"):
		buf_idx=0
		size_idx=-1
	elif(func_name==".memcpy"):
		buf_idx=0
		size_idx=2
	elif(func_name==".strncpy"):
		buf_idx=0
		size_idx=2
	elif(func_name==".strncat"):
		buf_idx=0
		size_idx=2
	elif(func_name==".snprintf"):
		buf_idx=0
		size_idx=1
	return buf_idx,size_idx

def get_brace(string):
	count=0
	idx=0
	for s in string:
		if(s=='('):
			count=count+1
		elif(s==')'):
			if(not count):
				break
			count=count-1
		idx=idx+1
	return idx

def get_arg(func_name,psecode,arg_idx):
	psecode=psecode.split(func_name)[1]
	r_idx=get_brace(psecode[1:])
	psecode=psecode[1:r_idx+1]
	arg_list=psecode.replace(' ,',',').split(',')
	return arg_list[arg_idx]

def find_in_code(code,name):
	for i in range(2,len(code)):
		if(name in code[i]):
			line=code[i]
			break
	return line


def check_stack_overflow(co,buf_idx,size_idx):
	global test_t
	likely_overflow=None
	if(size_idx>0):
		psecode=''
		addr=co.ea
		while(not co.name[1:] in psecode):
			psecode=du.display_line_at(addr,silent=True)
			addr=prev_head(addr)

		buf_o=get_arg(co.name[1:],psecode,buf_idx)
		size_o=get_arg(co.name[1:],psecode,size_idx)

		#buf=get_true_para(buf_o,1)
		'''if(buf_o.type=='unk'):
			print(hex(buf_o.val.ea))
			if(not str(type(buf_o.val)) in test_t):
				test_t.append(str(type(buf_o.val)))'''
		'''if("my_var_t" in str(type(buf_o.val))):
			print(buf_o.val.name)
		elif("cexpr_t" in str(type(buf_o.val))):
			print("test",buf_o.val.opname)'''
		if('a' in buf_o or 'a' in size_o):
			likely_overflow="low"
			return likely_overflow
		var_list=du.get_function_vars(c=co.c)
		size_var=None
		for var in var_list:
			if(var_list[var].name in buf_o):
				buf_var=var_list[var]
			elif(var_list[var].name in size_o):
				size_var=var_list[var]
		if(size_var):
			likely_overflow="low"
		else:# the size is a constant
			size_o=size_o.replace('L','').replace('u','')
			if('0x' in size_o):
				size=int(size_o,16)
			else:
				size=int(size_o)
			if(buf_var.is_array):
				buf_size=buf_var.array_len
			elif(buf_o[1]=='&'):
				code=du.lines_and_code(cf=co.c.cf)
				var_line=find_in_code(code,buf_o[2:])
				idx=var_line.find("rbp")
				if(idx>=0):
					r_idx=var_line[idx:].index(']')
					var_line=var_line[idx:idx+r_idx]
					buf_size=int(var_line.split('-')[-1][:-1],16)
				else:
					buf_size=size+1# get buf size failed
					likely_overflow="medium"
			else:
				buf_size=size+1# get buf size failed
				likely_overflow="medium"

			if(size>buf_size):
				likely_overflow="high"
	else:
		likely_overflow="medium"

	return likely_overflow

#def check_command_inject(co):
#	code=du.lines_and_code(cf=co.c.cf)
#	for i in code:
#		line=code[i]


dangerous_functions=[
	".strcpy",
	".strncpy",
	".memcpy",
	".strcat",
	".strncat",
	".sprintf",
	".snprintf",
	".read",
]

command_execution_function=[
	".system", 
	".execve",
	".popen",
	".unlink"
]


table_head=["func_name","addr","risk level"]
overflow_table=PrettyTable(table_head)

for func_name in dangerous_functions:
	calls=du.find_all_calls_to(func_name)
	for co in calls:
		info=[func_name[1:]]
		buf_idx,size_idx=get_para(func_name)
		level=check_stack_overflow(co,buf_idx,size_idx)
		if(level):
			info.append(hex(co.ea))
			info.append(level)
			overflow_table.add_row(info)

'''execute_table=PrettyTable(table_head)
for func_name in command_execution_function:
	calls=du.find_all_calls_to(func_name)
	for co in calls:
		info=[func_name[1:]]
		level=check_command_inject(co)'''


print(overflow_table)