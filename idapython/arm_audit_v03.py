from idaapi import *
from idautils import *
from idc import *
from ida_gdl import *
from prettytable import PrettyTable
import ida_bytes
import ida_idaapi
import ida_kernwin
import math

class arg_tracer():
	def __init__(self, addr, reg_index, bit, max_count=512, path_nodes=None):
		self.bit=bit
		if(self.bit==32):
			self.registers=[i for i in range(16)]#R0-R12 SP LR PC
		else:
			self.registers=[i+129 for i in range(33)]#X0-X29 LR PC SP
		self.init_trace_addr(addr)
		self.trace_reg=self.registers[reg_index]
		self.max_count=max_count
		self.function_head=get_func_attr(addr,FUNCATTR_START)
		try:
			func=get_func(addr)
			self.cfg=FlowChart(func)
		except:
			#if(self.bit==64):
			#	self.cfg=None
			#	print("fail to acquire the flowchart at %s,please check the disassembly"%(str(hex(addr))))
			func_head=self.get_function_head(addr)
			add_func(func_head)
			func=get_func(addr)
			self.cfg=FlowChart(func)

		self.results=[]
		self.string_results=[]
		if(path_nodes):
			self.path_nodes=path_nodes
		else:
			self.path_nodes=[addr]
		self.if_shrink=False
		self.result_addr=None
		self.base_reg=None
		self.offset=None
		self.if_mem=False

		self.not_assign_op=[ARM_not,ARM_neg,ARM_cmp,ARM_push,ARM_tst]#opcode that won't lead data to flow
		self.three_opnum_ins=[ARM_and,ARM_orr,ARM_eor,ARM_add,ARM_sub,ARM_rsb,ARM_mul,ARM_udiv,ARM_sdiv,ARM_bic]
		self.w2mem=[ARM_str]#opcode that write to memory
		self.mem2r=[ARM_ldr]#opcode that read from memory


	def blk_search(self,start_addr,end_addr):#trace in a basic block
		addr=start_addr
		if_finish=False
		while(not (addr==end_addr)):
			inst = insn_t()
			decode_insn(inst,addr)
			#print(hex(start_addr),hex(addr),hex(end_addr),self.if_mem,self.trace_reg-129)
			if(not self.if_mem and inst.Op1.type==o_reg and inst.Op1.reg==self.trace_reg and not(inst.itype in self.not_assign_op)):#confirm if the reg's value is derived from other registers
				if(inst.itype in self.three_opnum_ins):
					self.result_addr=addr
					next_reg=[]
					if(inst.Op2.type==o_reg):
						next_reg.append(inst.Op2.reg)
					if(inst.Op3.type==o_reg):
						next_reg.append(inst.Op3.reg)
					result=["",""]
					i=0
					for reg in next_reg:
						self.base_reg=reg
						result[i],if_shrink=self.trace_base_reg()
						if(if_shrink):
							self.string_results.append(result[i])
							if_finish=True
							self.if_mem=False
							self.result_addr=None
							return if_finish
						i=i+1
					self.put_together(inst,result)
					if_finish=True
					self.if_mem=False
					self.result_addr=None
					return if_finish
				else:
					if(inst.Op2.type==o_reg):
						self.trace_reg=inst.Op2.reg
						self.result_addr=addr
						self.if_mem=False
					elif(inst.itype in self.mem2r):
						self.offset=inst.Op2.__get_addr__()
						self.base_reg=inst.Op2.__get_reg_phrase__()
						self.result_addr=addr
						self.if_mem=True
						if(self.bit==32 and self.base_reg==self.registers[15]):
							self.string_results.append(print_operand(addr,1))
							if_finish=True
							self.result_addr=None
							self.if_mem=False
							self.if_shrink=True
							return if_finish
						result,if_shrink=self.trace_base_reg()
						if(result):
							if(not if_shrink):
								result=result+" => "+print_operand(addr,1)
							self.string_results.append(result)
							self.result_addr=None
							if_finish=True
							self.if_mem=False
							return if_finish
					elif(inst.Op2.type==o_imm):
						self.result_addr=addr
						if_finish=True
						self.if_mem=False
						return if_finish
			elif(self.if_mem and inst.itype in self.w2mem):
				offset=inst.Op2.__get_addr__()
				base_reg=inst.Op2.__get_reg_phrase__()
				if(offset==self.offset and base_reg==self.base_reg):
					if(inst.Op1.type==o_reg):
						self.trace_reg=inst.Op1.reg
						self.result_addr=addr
						self.if_mem=False
					else:
						self.result_addr=addr
						if_finish=True
						self.if_mem=False
						return if_finish
			elif(not self.if_mem and self.trace_reg==self.registers[0] and inst.itype==ARM_bl):#when tracing the r0,we can also search for "BL"
				self.result_addr=addr
				if_finish=True
				self.if_mem=False
				return if_finish
			addr=prev_head(addr)
		return if_finish

	def trace_base_reg(self):
		if(self.bit==64 and (self.base_reg==self.registers[29] or self.base_reg==self.registers[32])):
			#base_reg==X29 or SP
			return None,None
		elif(self.bit==32 and (self.base_reg==self.registers[11] or self.base_reg==self.registers[13])):
			#base_reg==R11 or SP
			return None,None
		else:
			if(self.bit==64):
				tracer=arg_tracer(self.result_addr,self.base_reg-129,self.bit,path_nodes=self.path_nodes)
			else:
				tracer=arg_tracer(self.result_addr,self.base_reg,self.bit,path_nodes=self.path_nodes)
			results,string_results=tracer.find_arg()
			if_shrink=tracer.get_if_shrink()
			if(results or string_results):
				targets=""
				for result in results:
					inst = insn_t()
					decode_insn(inst,result)
					if(inst.itype==ARM_ldr):
						target=print_operand(result,1)
					elif(inst.itype==ARM_str):
						target=print_operand(result,0)
						if(inst.Op1.type==o_reg):
							if(self.bit==64 and inst.Op1.reg<=self.registers[7] and inst.Op1.reg>=self.registers[0]):
								target='a'+str(inst.Op1.reg-128)
							elif(self.bit==32 and inst.Op1.reg<=self.registers[3] and inst.Op1.reg>=self.registers[0]):
								target='a'+str(inst.Op1.reg+1)
					elif(inst.itype==ARM_bl):
						target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
					else:
						target=print_operand(result,1)
						if(inst.Op2.type==o_reg): 
							if(self.bit==64 and inst.Op2.reg<=self.registers[7] and inst.Op2.reg>=self.registers[0]):
								target='a'+str(inst.Op2.reg-128)
							elif(self.bit==32 and inst.Op1.reg<=self.registers[3] and inst.Op1.reg>=self.registers[0]):
								target='a'+str(inst.Op1.reg+1)
					if(not target in targets):
						targets+=target+" or "
				for string_result in string_results:
					targets+=string_result+" or "
				return targets[:-4],if_shrink
			else:
				return print_operand(self.result_addr,1),if_shrink

	def get_if_shrink(self):
		return self.if_shrink

	def put_together(self,inst,result):
		opcode=inst.itype
		opnum2=print_operand(self.result_addr,1)
		opnum3=print_operand(self.result_addr,2)
		if(result[0]):
			string1="(%s)%s"%(result[0],opnum2)
		elif(inst.Op2.type==o_imm):
			string1=str(hex(inst.Op2.__get_value__()))
		else:
			string1=opnum2
		if(result[1]):
			string2="(%s)%s"%(result[1],opnum3)
		elif(inst.Op3.type==o_imm):
			string2=str(hex(inst.Op3.__get_value__()))
		else:
			string2=opnum3
		if(opcode==ARM_add):
			temp=string1+" + "+string2
		elif(opcode==ARM_sub):
			temp=string1+" - "+string2
		elif(opcode==ARM_mul):
			temp=string1+" x "+string2
		elif(opcode==ARM_sdiv or opcode==ARM_udiv):
			temp=string1+" / "+string2
		elif(opcode==ARM_and):
			temp=string1+" & "+string2
		elif(opcode==ARM_orr):
			temp=string1+" | "+string2
		elif(opcode==ARM_eor):
			temp=string1+" ^ "+string2
		elif(opcode==ARM_rsb):
			temp=string2+" - "+string1
		elif(opcode==ARM_bic):
			temp=string1+" & ~"+string2
		self.string_results.append(temp.replace('- -','+ '))

	def get_function_head(self,addr):
		c_addr=addr
		if(self.bit==32):
			target_opcode=ARM_push
		else:
			target_opcode=ARM_stp
		while(True):
			inst=insn_t()
			decode_insn(inst,c_addr)
			if(inst.itype==target_opcode):
				result=c_addr
				break
			c_addr=prev_head(c_addr)
		return result

	def dfs(self,addrs):#search from basic block to basic block,implement dfs 
		addr=None
		if(len(self.path_nodes)>self.max_count):
			if(self.result_addr and not self.result_addr in self.results):
				self.results.append(self.result_addr)
			return
		for addr in addrs:
			end_addr=None
			if_continue=True
			for blk in self.cfg:
				if(blk.start_ea<=addr and addr<blk.end_ea):#seek the basic block where the addr is
					end_addr=blk.start_ea
			if(not end_addr):
				return None
			if_finish=self.blk_search(addr,prev_head(end_addr))
			if(if_finish):
				if(self.result_addr):
					self.results.append(self.result_addr)
				if_continue=False
			if(not (end_addr==self.function_head) and if_continue):#if the function is over or seek the source of reg successfully
				xrefs=CodeRefsTo(end_addr,0)
				true_addrs=[]
				xref=None
				for xref in xrefs:
					if(not xref in self.path_nodes):
						self.path_nodes.append(xref)
						true_addrs.append(xref)
				if(not xref):#maybe need to be optimized
					xref=prev_head(end_addr)
					if(not xref in self.path_nodes):
						self.path_nodes.append(xref)
						true_addrs.append(xref)
				self.dfs(true_addrs)
		if(self.result_addr and not self.result_addr in self.results):
			self.results.append(self.result_addr)

	def init_trace_addr(self,addr):
		xrefs=CodeRefsTo(addr,0)
		self.trace_addr=[]
		for xref in xrefs:
			self.trace_addr.append(xref)
		
		prev_addr=prev_head(addr)
		inst = insn_t()
		decode_insn(inst,prev_addr)
		if(not (inst.itype==ARM_b)):
			self.trace_addr.append(prev_addr)
	
	def find_arg(self):
		if(self.cfg):
			self.dfs(self.trace_addr)
		return self.results,self.string_results

def fold_output(results):
	one_line_chars=20
	result_list=results.split("\n")
	result=""
	for x in result_list:
		add_line_times=math.ceil(len(x)/one_line_chars)
		tmp=""
		for i in range(add_line_times):
			tmp=tmp+x[i*one_line_chars:(i+1)*one_line_chars]+"\n"
		result=result+tmp+"\n"
	return result
	#return results


class result_display(ida_kernwin.Choose):
	def __init__(self,title,cols,item):
		ida_kernwin.Choose.__init__(self,title=title,cols=cols,flags=(ida_kernwin.Choose.CH_QFLT | ida_kernwin.Choose.CH_NOIDB))
		self.build_items(item)

	def OnGetSize(self):
		return len(self.items)

	def OnGetLine(self, n):
		result=[]
		for item in self.items[n]:
			result.append(item)
		return result

	def OnSelectLine(self,n):
		data=self.items[n]
		addr=data[0]
		if(not addr or not ida_bytes.is_loaded(int(addr,16))):
			print("无效的地址")
			return
		widget=self.find_disass_view()
		if not widget:
			print("无法定位反汇编窗口")
			return
		ida_kernwin.activate_widget(widget,True)
		ida_kernwin.jumpto(int(addr,16))
		return (ida_kernwin.Choose.NOTHING_CHANGED, )

	def find_disass_view(self):
		for c in map(chr, range(65, 75)):
			widget=ida_kernwin.find_widget('IDA View-%s'%c)
			if(widget):
				return widget
		return None

	def build_items(self, items):
		self.items=[]
		for item in items:
			self.items.append(item)


class dialog(ida_kernwin.Form):#main menu
	def __init__(self,bit):
		ida_kernwin.Form.__init__(self,"""
主菜单:
<##查看敏感函数:{btn_show_interesting_functions}><##分析函数参数:{btn_trace_arguments}>
""",{
		'btn_show_interesting_functions':ida_kernwin.Form.ButtonInput(self.show_interesting_functions),
		'btn_trace_arguments':ida_kernwin.Form.ButtonInput(self.trace_arguments)
})
		self.bit=bit
		self.init_interesting_functions()

	def init_interesting_functions(self):
		self.dangerous_functions=[
			".strcpy",
			".strcat",
			".sprintf",
			".read",
			".getenv"
		]

		self.attention_function=[
			".memcpy",
			".strncpy",
			".sscanf", 
			".strncat", 
			".snprintf",
			".vprintf", 
			".printf"
		]

		self.command_execution_function=[
			".system", 
			".execve",
			".popen",
			".unlink"
		]

		self.one_arg_function=[
			".getenv",
			".system",
			".unlink"
		]

		self.two_args_function=[
			".strcpy", 
			".strcat",
			".popen"
		]

		self.three_args_function=[
			".strncpy",
			".strncat", 
			".memcpy",
			".execve",
			".read"
		]

		self.format_function_offset_dict={
			".sprintf":1,
			".sscanf":1,
			".snprintf":2,
			".vprintf":0,
			".printf":0
		}

	def show_interesting_functions(self,code=0):
		func_list=[]
		for func_addr in Functions():
			func_name=get_func_name(func_addr)
			if(self.bit==32):
				func_name='.'+func_name
			if(func_name in self.dangerous_functions or func_name in self.attention_function or func_name in self.command_execution_function):
				func_list.append([str(hex(func_addr)),func_name[1:]])
		cols=[['函数地址', 10 | ida_kernwin.Choose.CHCOL_HEX],['函数名', 10 | ida_kernwin.Choose.CHCOL_PLAIN]]
		display=result_display(title='存在的敏感函数',cols=cols,item=func_list)
		display.Show()

	def trace_arguments(self,code=0):
		func_name='.'+ida_kernwin.ask_str('',0,'请输入要分析的敏感函数')
		if(self.bit==32):
			func_addr=self.get_func_addr(func_name[1:])
		else:
			func_addr=self.get_func_addr(func_name)
		if(not func_addr):
			print("无效的函数名")
			return
		if(func_name in self.format_function_offset_dict):
			cols,info=self.audit_fmt(func_name,func_addr)
		else:
			cols,info=self.audit(func_name,func_addr)
		display=result_display(title='%s数据流分析结果'%func_name[1:],cols=cols,item=info)
		display.Show()

	def get_func_addr(self,func_name):
		for func_addr in Functions():
			if(get_func_name(func_addr)==func_name):
				return func_addr
		return None

	def audit(self,func_name,func_addr):
		if func_name in self.one_arg_function:
			arg_num=1
		elif func_name in self.two_args_function:
			arg_num=2
		elif func_name in self.three_args_function:
			arg_num=3
		else:
			print("%s 函数未注册，请加入到插件的函数列表中" % func_name)
			return
		total_info=[]
		table_head=[["addr",10 | ida_kernwin.Choose.CHCOL_HEX]]
		for num in range(0,arg_num):
			table_head.append(["arg"+str(num+1),10 | ida_kernwin.Choose.CHCOL_PLAIN])
		table_head.append(["local_buf_size",10 | ida_kernwin.Choose.CHCOL_PLAIN])
		xrefs=CodeRefsTo(func_addr,0)
		for xref in xrefs:
			set_color(xref,CIC_ITEM,0x00ff00)
			info=[hex(xref)]
			local_buf_size=get_func_attr(xref,FUNCATTR_FRSIZE)
			if(local_buf_size==BADADDR):
				local_buf_size="fail"
			else:
				local_buf_size="0x%x" % local_buf_size
			for i in range(arg_num):
				tracer=arg_tracer(xref,i,self.bit)
				results,string_results=tracer.find_arg()
				if(results or string_results):
					targets=""
					for result in results:
						inst = insn_t()
						decode_insn(inst,result)
						if(inst.itype==ARM_ldr):
							target=print_operand(result,1)
						elif(inst.itype==ARM_str):
							if(self.bit==64 and inst.Op1.reg<=136 and inst.Op1.reg>=129):
								target='a'+str(inst.Op1.reg-128)
							elif(self.bit==32 and inst.Op1.reg<=3 and inst.Op1.reg>=0):
								target='a'+str(inst.Op1.reg+1)
							else:
								target=print_operand(result,0)
						elif(inst.itype==ARM_bl):
							target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
						else:
							if(self.bit==64 and inst.Op2.reg<=136 and inst.Op2.reg>=129):
								target='a'+str(inst.Op2.reg-128)
							elif(self.bit==32 and inst.Op2.reg<=3 and inst.Op2.reg>=0):
								target='a'+str(inst.Op2.reg+1)
							else:
								target=print_operand(result,1)
						if(not target in targets):
							targets+=target+"\t"
					for string_result in string_results:
						targets+=string_result+"\t"
					#targets=fold_output(targets)
					info.append(targets[:-1])
				else:
					info.append("fail")
			info.append(local_buf_size)
			total_info.append(info)
		return table_head,total_info

	def audit_fmt(self,func_name,func_addr):
		total_info=[]
		f_idx=self.format_function_offset_dict[func_name]
		table_head=[["addr",10 | ida_kernwin.Choose.CHCOL_HEX]]
		for num in range(0,6):
			table_head.append(["arg"+str(num+1),10 | ida_kernwin.Choose.CHCOL_PLAIN])
		table_head[f_idx+1]=["fmt",10 | ida_kernwin.Choose.CHCOL_PLAIN]
		table_head.append(["local_buf_size",10 | ida_kernwin.Choose.CHCOL_PLAIN])
		xrefs=CodeRefsTo(func_addr,0)
		for xref in xrefs:
			set_color(xref,CIC_ITEM,0x00ff00)
			local_buf_size=get_func_attr(xref,FUNCATTR_FRSIZE)
			if(local_buf_size==BADADDR):
				local_buf_size="fail"
			else:
				local_buf_size="0x%x" % local_buf_size
			info=["NULL" for i in range(7)]
			info[0]=hex(xref)
			tracer=arg_tracer(xref,f_idx,self.bit)
			results,string_results=tracer.find_arg()
			targets=""
			fmt_num=0
			result=None
			for result in results:
				if(not get_operand_type(result,1)==o_imm):
					if(not "fmt" in targets):
						targets+="maybe a fmt vuln\n"
				else:
					op_string=print_operand(result,1).split(" ")[0].split("+")[0].split("-")[0].replace("(","")
					fmt_addr=get_name_ea_simple(op_string)
					fmt_string=get_strlit_contents(fmt_addr).decode('utf-8')
					temp_fmt_num=str.count(fmt_string,"%")
					if(temp_fmt_num>fmt_num):
						fmt_num=temp_fmt_num
					targets+=fmt_string+"\t"
			if(not result and not string_results):
				info[f_idx+1]="maybe a fmt vuln"
			else:
				if(not result):
					target=string_results[0]
					op_string=target.split(" ")[0].split("@")[0].split("-")[0].replace("(","").replace("#","").replace("=","")
					fmt_addr=get_name_ea_simple(op_string)
					fmt_string=get_strlit_contents(fmt_addr).decode('utf-8')
					fmt_num=str.count(fmt_string,"%")
					info[f_idx+1]=fmt_string
				else:
					#targets=fold_output(targets)
					info[f_idx+1]=targets[:-1]
				for i in range(f_idx+1,fmt_num+f_idx+1):#find format string's arguments
					if(i==6):#6 arguments at most
						break
					tracer=arg_tracer(xref,i,self.bit)
					results,string_results=tracer.find_arg()
					if(results or string_results):
						targets=""
						for result in results:
							inst = insn_t()
							decode_insn(inst,result)
							if(inst.itype==ARM_ldr):
								target=print_operand(result,1)
							elif(inst.itype==ARM_str):
								if(self.bit==64 and inst.Op1.type==o_reg and inst.Op1.reg<=136 and inst.Op1.reg>=129):
									target='a'+str(inst.Op1.reg-128)
								elif(self.bit==32 and inst.Op1.type==o_reg and inst.Op1.reg<=3 and inst.Op1.reg>=0):
									target='a'+str(inst.Op1.reg+1)
								else:
									target=print_operand(result,0)
							elif(inst.itype==ARM_bl):
								target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
							else:
								if(self.bit==64 and inst.Op2.type==o_reg and inst.Op2.reg<=136 and inst.Op2.reg>=129):
									target='a'+str(inst.Op2.reg-128)
								elif(self.bit==32 and inst.Op2.type==o_reg and inst.Op2.reg<=3 and inst.Op2.reg>=0):
									target='a'+str(inst.Op2.reg+1)
								else:
									target=print_operand(result,1)
							if(not target in targets):
								targets+=target+"\t"
						for string_result in string_results:
							targets+=string_result+"\t"
						#targets=fold_output(targets)
						info[i+1]=targets[:-1]
					else:
						info[i+1]="fail"

			for i in range(f_idx):#find arguments before the format string
				tracer=arg_tracer(xref,i,self.bit)
				results,string_results=tracer.find_arg()
				if(results or string_results):
					targets=""
					for result in results:
						inst = insn_t()
						decode_insn(inst,result)
						if(inst.itype==ARM_ldr):
							target=print_operand(result,1)
						elif(inst.itype==ARM_str):
							if(self.bit==64 and inst.Op1.type==o_reg and inst.Op1.reg<=136 and inst.Op1.reg>=129):
								target='a'+str(inst.Op1.reg-128)
							elif(self.bit==32 and inst.Op1.type==o_reg and inst.Op1.reg<=3 and inst.Op1.reg>=0):
								target='a'+str(inst.Op1.reg+1)
							else:
								target=print_operand(result,0)
						elif(inst.itype==ARM_bl):
							target=str(print_operand(result,0))+"(%s)\'s ret"%str(hex(result))
						else:
							if(self.bit==64 and inst.Op2.type==o_reg and inst.Op2.reg<=136 and inst.Op2.reg>=129):
								target='a'+str(inst.Op2.reg-128)
							elif(self.bit==32 and inst.Op2.type==o_reg and inst.Op2.reg<=3 and inst.Op2.reg>=0):
								target='a'+str(inst.Op2.reg+1)
							else:
								target=print_operand(result,1)
						if(not target in targets):
							targets+=target+"\t"
					for string_result in string_results:
							targets+=string_result+"\t"
					#targets=fold_output(targets)
					info[i+1]=targets[:-1]
				else:
					info[i+1]="fail"
			info.append(local_buf_size)
			total_info.append(info)
		return table_head,total_info



class analyzer(ida_kernwin.action_handler_t):#trigger 
	def __init__(self,bit):
		ida_kernwin.action_handler_t.__init__(self)
		self.bit=bit

	def show_menu(self):
		main=dialog(self.bit)
		main.Compile()
		main.Execute()

	def activate(self,ctx):
		self.show_menu()

	def update(self,ctx):
		return ida_kernwin.AST_ENABLE_ALWAYS

class arm_audit(ida_idaapi.plugin_t):#register menu
	help = "help"
	flags = ida_idaapi.PLUGIN_KEEP
	wanted_name = "arm_audit"
	wanted_hotkey = "Ctrl+F1"
	comment = "This is my embedded system large homework"
	audit_analyzer='test'

	def init(self):
		ida_idaapi.plugin_t.__init__(self)
		self.MENU_PATH="Edit/Plugins/"
		arch=get_inf_structure()
		if(arch.is_64bit()):
			self.bit=64
		elif(arch.is_32bit()):
			self.bit=32
		else:
			print("Running on the arch that this plugin doesn't support")
			return ida_idaapi.PLUGIN_HIDE

		action=ida_kernwin.action_desc_t(self.audit_analyzer,'显示主菜单',analyzer(self.bit),'Ctrl+Shift+a','插件主菜单',0)
		ida_kernwin.register_action(action)
		ida_kernwin.attach_action_to_menu(self.MENU_PATH,self.audit_analyzer,ida_kernwin.SETMENU_APP)
		return ida_idaapi.PLUGIN_KEEP

	def term(self):
		ida_kernwin.detach_action_from_menu(self.MENU_PATH,self.audit_analyzer)

	def run(self,arg):
		msg("run successfully")


def PLUGIN_ENTRY():
	return arm_audit()