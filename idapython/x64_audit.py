from idaapi import *
from idautils import *
from idc import *
from ida_gdl import *
from prettytable import PrettyTable


def blk_find_reg(start_addr,end_addr,reg):
	global not_assign_op
	addr=start_addr
	target_addr=None
	sign=0
	while(not (addr==end_addr)):
		inst = insn_t()
		decode_insn(inst,addr)
		#print(hex(start_addr),hex(addr),hex(end_addr),reg,inst.itype,NN_call,inst.Op1.type==o_reg,inst.Op1.reg==reg)
		if (inst.Op1.type==o_reg and inst.Op1.reg==reg and not(inst.itype in not_assign_op)):
			if(inst.Op2.type==o_reg):
				reg=inst.Op2.reg
				sign=inst.Op2.reg
				target_addr=addr
				#print(1,hex(start_addr),hex(addr),hex(end_addr))
			else:
				#print(2,hex(start_addr),hex(addr),hex(end_addr))
				sign=-1
				return addr,sign
		elif(reg==0 and NN_call<=inst.itype and inst.itype<=NN_callni):#when tracing the rax,we can also search for "call"
			sign=-1
			return addr,sign
		addr=prev_head(addr)
	return target_addr,sign

def dfs(addrs,reg,cfg,function_head):
	global results,max_count,target_reg,path_nodes
	addr=None
	if(len(path_nodes)>max_count):
		if(target_reg and not target_reg in results):
			results.append(target_reg)
		return
	for addr in addrs:
		end_addr=None
		if_continue=1
		for blk in cfg:
			if(blk.start_ea<=addr and addr<blk.end_ea):
				end_addr=blk.start_ea
		if(not end_addr):
			return None
		target_addr,sign=blk_find_reg(addr,prev_head(end_addr),reg)
		if(target_addr):
			target_reg=target_addr
			if(sign==-1):
				results.append(target_reg)
				if_continue=0
			else:
				reg=sign
		if(not (end_addr==function_head) and if_continue):
			xrefs=CodeRefsTo(end_addr,0)
			true_addrs=[]
			xref=None
			for xref in xrefs:
				if(not xref in path_nodes):
					path_nodes.append(xref)
					true_addrs.append(xref)
			if(not xref):
				xref=prev_head(end_addr)
				if(not xref in path_nodes):
					path_nodes.append(xref)
					true_addrs.append(xref)
			dfs(true_addrs,reg,cfg,function_head)
	if(target_reg and not target_reg in results):
		results.append(target_reg)


def find_arg(addr,index):
	global results,enum_r,target_reg,path_nodes
	function_head=get_func_attr(addr,FUNCATTR_START)
	func=get_func(addr)
	cfg=FlowChart(func)
	r_index=enum_r[index]
	results.clear()
	target_reg=None
	path_nodes=[addr]
	dfs([addr],r_index,cfg,function_head)


def audit(func_name,func_addr):
	global results
	if func_name in one_arg_function:
		arg_num=1
	elif func_name in two_args_function:
		arg_num=2
	elif func_name in three_args_function:
		arg_num=3
	else:
		print("The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name)
		return
	table_head=["func_name","addr"]
	for num in range(0,arg_num):
		table_head.append("arg"+str(num+1))
	table_head.append("local_buf_size")
	table=PrettyTable(table_head)
	xrefs=CodeRefsTo(func_addr,0)
	for xref in xrefs:
		set_color(xref,CIC_ITEM,0x00ff00)
		info=[func_name,hex(xref)]
		local_buf_size=get_func_attr(xref,FUNCATTR_FRSIZE)
		if(local_buf_size==BADADDR):
			local_buf_size="fail"
		else:
			local_buf_size="0x%x" % local_buf_size
		for i in range(arg_num):
			find_arg(xref,i)
			if(results):
				targets=""
				for result in results:
					target=print_operand(result,1)
					if(print_insn_mnem(result).lower()=="lea"):
						if(not "[" in target):
							op_string=target.split(" ")[0].split("+")[0].split("-")[0].replace("(","")
							target=str(hex(get_name_ea_simple(op_string)))
						else:
							target=target[1:-1]
					elif(print_insn_mnem(result).lower()=="call"):
						target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
					if(not target in targets):
						targets+=target+"\n"
				info.append(targets[:-1])
			else:
				info.append("fail")
		info.append(local_buf_size)
		table.add_row(info)
	print(table)


def audit_fmt(func_name,func_addr):
	global results
	f_idx=format_function_offset_dict[func_name]
	table_head=["func_name","addr"]
	for num in range(0,6):
		table_head.append("arg"+str(num+1))
	table_head[f_idx+2]="fmt"
	table_head.append("local_buf_size")
	table=PrettyTable(table_head)
	xrefs=CodeRefsTo(func_addr,0)
	for xref in xrefs:
		set_color(xref,CIC_ITEM,0x00ff00)
		local_buf_size=get_func_attr(xref,FUNCATTR_FRSIZE)
		if(local_buf_size==BADADDR):
			local_buf_size="fail"
		else:
			local_buf_size="0x%x" % local_buf_size
		info=["NULL" for i in range(8)]
		info[0]=func_name
		info[1]=hex(xref)
		find_arg(xref,f_idx)
		targets=""
		fmt_num=0
		for result in results:
			if(not get_operand_type(result,1)==2 and not "fmt" in targets):
				targets+="maybe a fmt vuln\n"
			else:
				op_string=print_operand(result,1).split(" ")[0].split("+")[0].split("-")[0].replace("(","")
				fmt_addr=get_name_ea_simple(op_string)
				fmt_string=str(get_strlit_contents(fmt_addr))
				temp_fmt_num=str.count(fmt_string,"%")
				if(temp_fmt_num>fmt_num):
					fmt_num=temp_fmt_num
				targets+=str(hex(fmt_addr))+"\n"
		if(not fmt_num):
			info[f_idx+2]="maybe a fmt vuln"
		else:
			info[f_idx+2]=targets[:-1]
			for i in range(f_idx+1,fmt_num+f_idx+1):#find fmt's parameters
				if(i==6):
					break
				find_arg(xref,i)
				if(results):
					targets=""
					for result in results:
						target=print_operand(result,1)
						if(print_insn_mnem(result).lower()=="lea"):
							if(not "[" in target):
								op_string=target.split(" ")[0].split("+")[0].split("-")[0].replace("(","")
								target=str(hex(get_name_ea_simple(op_string)))
							else:
								target=target[1:-1]
						elif(print_insn_mnem(result).lower()=="call"):
							target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
						if(not target in targets):
							targets+=target+"\n"
					info[i+2]=targets[:-1]
				else:
					info[i+2]="fail"

		for i in range(f_idx):#find parameters before fmt
			find_arg(xref,i)
			if(results):
				targets=""
				for result in results:
					target=print_operand(result,1)
					if(print_insn_mnem(result).lower()=="lea"):
						if(not "[" in target):
							op_string=target.split(" ")[0].split("+")[0].split("-")[0].replace("(","")
							target=str(hex(get_name_ea_simple(op_string)))
						else:
							target=target[1:-1]
					elif(print_insn_mnem(result).lower()=="call"):
						target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
					if(not target in targets):
						targets+=target+"\n"
				info[i+2]=targets[:-1]
			else:
				info[i+2]="fail"
		info.append(local_buf_size)
		table.add_row(info)
	print(table)


global enum_r,results,not_assign_op,max_count,target_reg,path_nodes
enum_r=[7,6,2,1,8,9]
max_count=50
results=[]
path_nodes=[]
not_assign_op=[NN_cmp,NN_test,NN_and,NN_or,NN_xor,NN_add,NN_sub,NN_dec,NN_inc,NN_shl,NN_shr,NN_rol,NN_ror,NN_push,NN_pop]

dangerous_functions=[
	".strcpy",
	".strcat",
	".sprintf",
	".read",
	".getenv"
]

attention_function=[
	".memcpy",
	".strncpy",
	".sscanf", 
	".strncat", 
	".snprintf",
	".vprintf", 
	".printf"
]

command_execution_function=[
	".system", 
	".execve",
	".popen",
	".unlink"
]

one_arg_function=[
	".getenv",
	".system",
	".unlink"
]

two_args_function=[
	".strcpy", 
	".strcat",
	".popen"
]

three_args_function=[
	".strncpy",
	".strncat", 
	".memcpy",
	".execve",
	".read"
]

format_function_offset_dict={
	".sprintf":1,
	".sscanf":1,
	".snprintf":2,
	".vprintf":0,
	".printf":0
}

for func_addr in Functions():
	func_name=get_func_name(func_addr)
	if(func_name in dangerous_functions or func_name in attention_function or func_name in command_execution_function):
		if(func_name in format_function_offset_dict):
			audit_fmt(func_name,func_addr)
		else:
			audit(func_name,func_addr)
