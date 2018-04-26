import re
import idc
import idautils
import idaapi

class Auto_Name_Functions_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_KEEP
	comment = ''
	help = ''
	wanted_name = 'aan_Auto_Name_Functions'
	wanted_hotkey = 'ctrl-shift-a'
	
	def init(self):
		return idaapi.PLUGIN_KEEP
		
	def run(self, arg):
		Auto_Name_Function_Wrapper()
		
	def term(self):
		pass
		
def PLUGIN_ENTRY():
	return Auto_Name_Functions_t()
	
IDA_FUNC_PREFIX = 'sub_'
CUSTOM_FUNC_PREFIX = 'f_a__'
CUSTOM_MANUAL_FUNC_PREFIX = 'f__'
CUSTOM_JUMP_PREFIX = '_J__'

def Auto_Name_Function_Wrapper():
	ea = idc.ScreenEA()
	segStartEA = idc.SegStart(ea)
	segEndEA = idc.SegEnd(ea)
	
	print '=' * 100
	print 'aan_Auto_Name_Function Starting'
	
	excludeList = [entry[3] for entry in idautils.Entries()]
	excludeList.extend(['WinMain', 'WinMain@12', 'WinMain@16', 'wWinMain', 'wWinMain@12', 'wWinMain@16', '_wWinMain@12', '_wWinMain@16', 'main', '_main', 'StartAddress'])
	
	funcList = []
	for funcEa in idautils.Functions(segStartEA, segEndEA):
		flags = idc.GetFunctionFlags(funcEa)
		if ((flags & idc.FUNC_LIB) != idc.FUNC_LIB) and ((flags & idc.FUNC_THUNK) != idc.FUNC_THUNK) and (idc.GetFunctionName(funcEa) not in excludeList):
			funcList.append(funcEa)
			
	parentNodes = set()
	for funcEa in funcList:
		for refEA in idautils.CodeRefsTo(funcEa, 0):
			if idc.GetFunctionAttr(refEA, idc.FUNCATTR_START) != funcEa:
				parentNodes.add(idc.GetFunctionAttr(refEA, idc.FUNCATTR_START))
	
	leafNodes = []
	for funcEa in funcList:
		if funcEa not in parentNodes: 
			leafNodes.append(funcEa)
	
	threadRootsList = Get_Thread_Roots()
	threadRootsList = [threadEa for threadEa in threadRootsList[:] if idc.GetFunctionName(threadEa) not in excludeList]
	
	for funcEa in threadRootsList:
		if idc.GetFunctionFlags(funcEa) == -1:
			pass
		else:
			Rename(funcEa, CUSTOM_MANUAL_FUNC_PREFIX + 'TS')
			
	while True:
		funcRenamedCount = 0
		nodesTraversed = set()
		curNodes = leafNodes[:]
		
		while True:
			for funcEa in curNodes:
				if idc.GetFunctionName(funcEa).startsWith(CUSTOM_MANUAL_FUNC_PREFIX):
					continue
				oldFuncName = idc.GetFunctionName(funcEa)
				newFuncNameProposed = Build_New_Func_Name(funcEa)
				Rename(funcEa, newFuncNameProposed)
				newFuncNameActual = idc.GetFunctionName(funcEa)
				
				if oldFuncName != newFuncNameActual:
					funcRenamedCount += 1
					
			nodesTraversed.update(curNodes)
			parentNodes = set()
			
			for funcEa in curNodes:
				for refEA in idautils.CodeRefsTo(funcEa, 0):
					flags = idc.GetFunctionFlags(refEA)
					if ((flags & idc.FUNC_LIB) != idc.FUNC_LIB) and (idc.GetFunctionName(refEA) not in excludeList):
						if idc.GetFunctionAttr(refEA, idc.FUNCATTR_START) not in nodesTraversed:
							parentNodes.add(idc.GetFunctionAttr(refEA, idc.FUNCATTR_START))
							
			if len(parentNodes) == 0:
				break
				
			curNodes = parentNodes.copy()
			
		if funcRenamedCount == 0:
			break
			
	print 'aan_Auto_Name_Function completed'
	print '=' * 100
	Refresh()
	
	
def Get_Thread_Roots():
	funcNamesList = ['CreateThread', '_beginthreadex', '_beginthread']
	
	threadStartEaSet = set()
	for funcName in funcNamesList:
		argIndex = 1 if funcName == '_beginthread' else 3
		funcLoc = idc.LocByName(funcName)
		if funcLoc == idc.BADADDR:
			continue
			
		codeRefs = idautils.CodeRefsTo(funcLoc,0)
		dataRefs = idautils.DataRefsTo(funcLoc)
		refs = set(codeRefs) | set(dataRefs)
		
		for refEa in refs:
			if idc.GetMnem(refEa) == 'call':
				mnemEA = Get_Prev_Instruction(refEa, 'push', argIndex, 10)
				if mnemEA == -1:
					continue
					
				if idc.GetOpType(mnemEA,0) == idc.o_reg:
					reg = idc.GetOpnd(mnemEA, 0)
					for i in range(0,5):
						mnemEA = Get_Prev_Instruction(mnemEA, 'mov', 1, 10)
						if mnemEA == -1:
							break
						if idc.GetOpnd(mnemEA, 0) == reg:
							rootEa = idc.GetOperandValue(mnemEA, 1)
							if idc.GetFunctionName(rootEa) != '':
								threadStartEaSet.add(rootEa)
							break
				else:
					rootEa = idc.GetOperandValue(mnemEA,0)
					if idc.GetFunctionName(rootEa) != '':
						threadStartEaSet.add(rootEa)
					
	return list(threadStartEaSet)
	
	
	
	
def Rename(ea, inStr):
	returnVal = idc.MakeNameEx(ea, inStr, 0x100)
	if returnVal == 1:
		return 1
			
	for i in range(0,99):
		returnVal = idc.MakeNameEx(ea, inStr + "_" + str(i), 0x100)
			
		if returnVal == 1:
			return 1
		
	print 'Error, name {:s} already used and can not be automatically renamed'.format(inStr)
	return -1
		
def Get_Prev_Instruction(curEa, mnem, N, MAX_INSTRUCTIONS = 9999):
	funcStartEa = idc.GetFunctionAttr(curEa, idc.FUNCATTR_START)
	totalInstructionCount = 0
	targetInstructionCount = 0
	
	while (totalInstructionCount < MAX_INSTRUCTIONS) and (targetInstructionCount < N) and (curEa != idc.BADADDR):
		curEa = idc.PrevHead(curEa, funcStartEa)
		if idc.GetMnem(curEa) == mnem:
			targetInstructionCount += 1
		totalInstructionCount += 1
		
	if targetInstructionCount == N:
		result = curEa
	else:
		result = -1
		
	return result
	
def Get_Next_Instruction(curEa, mnem, N, MAX_INSTRUCTIONS = 9999):
	funcEndEa = idc.GetFunctionAttr(curEa, idc.FUNCATTR_END)
	totalInstructionCount = 0
	targetInstructionCount = 0
	
	while (totalInstructionCount < MAX_INSTRUCTIONS) and (targetInstructionCount < N) and (curEa != idc.BADADDR):
		curEa = idc.NextHead(curEa, funcStartEa)
		if idc.GetMnem(curEa) == mnem:
			targetInstructionCount += 1
		totalInstructionCount += 1
		
	if targetInstructionCount == N:
		result = curEa
	else:
		result = -1
		
	return result
	
def Build_New_Func_Name(funcEa):
	apiPurposeDict = {
		'socket': 'netwB',
		'connect': 'netwC',
		'InternetOpen': 'netwC',
		'InternetOpenURL': 'netwC',
		'InternetConnect': 'netwC',
		'HttpOpenRequest': 'netwC',
		'WinHttpOpen': 'netwC',
		'WinHttpConnect': 'netwC',
		'WinHttpOpenRequest': 'netwC',
		'bind': 'netwL',
		'listen': 'netwL',
		'accept': 'netwL',
		'send': 'netwS',
		'sendto': 'netwS',
		'InternetWriteFile': 'netwS',
		'HttpSendRequest': 'netwS',
		'WSASend': 'netwS',
		'WSASendTo': 'netwS',
		'WinHttpSendRequest': 'netwS',
		'WinHttpWriteData': 'netwS',
		'recv': 'netwR',
		'recvfrom': 'netwR',
		'InternetReadFile': 'netwR',
		'HttpReceiveHttpRequest': 'netwR',
		'WSARecv': 'netwR',
		'WSARecvFrom': 'netwR',
		'WinHttpReceiveResponse': 'netwR',
		'WinHttpReadData': 'netwR',
		'inet_addr': 'netwM',
		'htons': 'netwM',
		'htonl': 'netwM',
		'ntohs': 'netwM',
		'ntohl': 'netwM',
		'closesocket': 'netwT',
		'shutdown': 'netwT',
		'RegOpenKey': 'regH',
		'RegQueryValue': 'regR',
		'RegGetValue': 'regR',
		'RegEnumValue': 'regR',
		'RegSetValue': 'regW',
		'RegSetKeyValue': 'regW',
		'RegDeleteValue': 'regD',
		'RegDeleteKey': 'regD',
		'RegDeleteKeyValue': 'regD',
		'RegCreateKey': 'regC',
		'CreateFile': 'fileH',
		'fopen': 'fileH',
		'fscan': 'fileR',
		'fgetc': 'fileR',
		'fgets': 'fileR',
		'fread': 'fileR',
		'ReadFile': 'fileR',
		'flushfilebuffers': 'fileW',
		'fprintf': 'fileW',
		'fputc': 'fileW',
		'fputs': 'fileW',
		'fwrite': 'fileW',
		'WriteFile': 'fileW',
		'DeleteFile': 'fileD',
		'CopyFile': 'fileC',
		'MoveFile': 'fileM',
		'FindFirstFile': 'fileE',
		'FindNextFile': 'fileE',
		'strcmp': 'strC',
		'strncmp': 'strC',
		'stricmp': 'strC',
		'wcsicmp': 'strC',
		'mbsicmp': 'strC',
		'lstrcmp': 'strC',
		'lstrcmpi': 'strC',
		'OpenService': 'servH',
		'QueryServiceStatus': 'servR',
		'QueryServiceConfig': 'servR',
		'ChangeServiceConfig': 'servW',
		'ChangeServiceConfig2': 'servW',
		'CreateService': 'servC',
		'DeleteService': 'servD',
		'StartService': 'servS',
		'CreateToolHelp32Snapshot': 'procE',
		'Process32First': 'procE',
		'Process32Next': 'procE',
		'OpenProcess': 'procH',
		'CreateProcess': 'procC',
		'CreateProcessAsUser': 'procC',
		'CreateProcessWithLogon': 'procC',
		'CreateProcessWithToken': 'procC',
		'ShellExecute': 'procC',
		'ExitProcess': 'procT',
		'TerminateProcess': 'procT',
		'ReadProcessMemory': 'procR',
		'VirtualAlloc': 'procW',
		'WriteProcessMemory': 'procW',
		'CreateThread': 'threadC',
		'beginthreadex': 'threadC',
		'OpenThread': 'threadO',
		'SuspendThread': 'threadS',
		'ResumeThread': 'threadR'
	}
	
	funcStartEA = idc.GetFunctionAttr(funcEa, FUNCATTR_START)
	funcEndEA = idc.GetFunctionAttr(funcEa, FUNCATTR_END)
	funcOrigName = idc.GetFunctionName(funcEa)
	
	refToCount = len(list(idautils.CodeRefsTo(funcStartEA, 0)))
	
	callList = [head for head in idautils.Heads(funcStartEA, funcEndEA) if idc.GetMnem(head) == 'call']
	callList = [callEa for callEa in callList if idc.GetOperandValue(callEa,0) != funcStartEA]
	
	if len(callList) == 0:
		flags = idc.GetFunctionFlags(funcEa)
		if ((flags & idc.FUNC_THUNK) == idc.FUNC_THUNK) and (idc.GetMnem(funcEa) == 'jmp'):
			callList.append(funcEa)
		else:
			return '{}zc_{}{:X}__xref_{:02d}'.format(CUSTOM_FUNC_PREFIX, IDA_FUNC_PREFIX, funcEa, refToCount)
			
	apiUsed = {}
	for callEA in callList:
		pattern = re.compile('^(?!sub|loc_\d|e[abcd]x|e[sd]i|ebp|esp|dword|ds\:(?:dword|off_))(?:ds\:|cs\:|j_)?(?P<funcName>\w+)', re.IGNORECASE)
		match = re.search(pattern, idc.GetOpnd(callEA, 0))
		if match != None:
			pattern = '^(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:_\d)?$'
			match = re.search(pattern, match.group('funcName'))
			
			if match != None:
				curAPIName = match.group('baseName')
				if curAPIName in apiUsed:
					apiUsed[curAPIName]['count'] = apiUsed[curAPIName]['count'] + 1
				else:
					apiUsed[curAPIName] = { 'count': 1 }
					
	for callEA in callList:
		if (idc.GetOpType(callEA,0) == 1) and (";" in idc.GetDisasm(callEA)):
			curAPIName = idc.GetDisasm(callEA).split(';',1)[1].strip().strip('"')
			if len(curAPIName) > 1:
				pattern = '^(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:_\d)?$'
				match = re.search(pattern, curAPIName)
				curAPIName = match.group('baseName')
				
				if curAPIName in apiUsed:
					apiUsed[curAPIName]['count'] = apiUsed[curAPIName]['count'] + 1
				else:
					apiUsed[curAPIName] = {'count': 1}
					
	implementedAPIPurpose = set()
	for func in apiUsed.keys():
		implementedAPIPurpose.add(apiPurposeDict.get(func))
		
	childFunctionImplementedAPIPurpose = dict()
	for callEA in callList:
		funcName = idc.GetOpnd(callEA,0)
		if funcName.startwith(CUSTOM_FUNC_PREFIX) or funcName.startwith(CUSTOM_MANUAL_FUNC_PREFIX):
			categories = 'netw', 'reg', 'file', 'str', 'serv', 'thread', 'proc'
			for category in categories:
				pattern = category + '_' + '([a-zA-Z]+)+_?([a-zA-Z]+)?'
				match = re.search(pattern, funcName)
				
				if match is not None:
					apiPurpose = set()
					if match.group(1) is not None:
						apiPurpose.update(list(match.group(1).lower()))
					if match.group(2) is not None:
						apiPurpose.update(list(match.group(2).lower()))
					if category in childFunctionImplementedAPIPurpose:
						childFunctionImplementedAPIPurpose[category].update(apiPurpose)
					else:
						childFunctionImplementedAPIPurpose[category] = apiPurpose
						
	newFuncNamePurpose = ''
	str = ''
	if 'netwB' in implementedAPIPurpose: str += 'B'
	if 'netwC' in implementedAPIPurpose: str += 'C'
	if 'netwL' in implementedAPIPurpose: str += 'L'
	if 'netwS' in implementedAPIPurpose: str += 'S'
	if 'netwR' in implementedAPIPurpose: str += 'R'
	if 'netwT' in implementedAPIPurpose: str += 'T'
	if 'netwM' in implementedAPIPurpose: str += 'M'
	
	str1 = ''
	if 'netw' in childFunctionImplementedAPIPurpose:
		if 'b' in childFunctionImplementedAPIPurpose['netw']: str1 += 'b'
		if 'c' in childFunctionImplementedAPIPurpose['netw']: str1 += 'c'
		if 'l' in childFunctionImplementedAPIPurpose['netw']: str1 += 'l'
		if 's' in childFunctionImplementedAPIPurpose['netw']: str1 += 's'
		if 'r' in childFunctionImplementedAPIPurpose['netw']: str1 += 'r'
		if 't' in childFunctionImplementedAPIPurpose['netw']: str1 += 't'
		if 'm' in childFunctionImplementedAPIPurpose['netw']: str1 += 'm'
		
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'netw'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
		
	str = ''
	if 'regH' in implementedAPIPurpose: str += 'H'
	if 'regR' in implementedAPIPurpose: str += 'R'
	if 'regW' in implementedAPIPurpose: str += 'W'
	if 'regD' in implementedAPIPurpose: str += 'D'
	
	str1 = ''
	if 'reg' in childFunctionImplementedAPIPurpose:
		if 'h' in childFunctionImplementedAPIPurpose['reg']: str1 += 'h'
		if 'r' in childFunctionImplementedAPIPurpose['reg']: str1 += 'r'
		if 'w' in childFunctionImplementedAPIPurpose['reg']: str1 += 'w'
		if 'd' in childFunctionImplementedAPIPurpose['reg']: str1 += 'd'
		
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'reg'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
		
	str = ''
	if 'fileH' in implementedAPIPurpose: str += 'H'
	if 'fileR' in implementedAPIPurpose: str += 'R'
	if 'fileW' in implementedAPIPurpose: str += 'W'
	if 'fileD' in implementedAPIPurpose: str += 'D'
	if 'fileC' in implementedAPIPurpose: str += 'C'
	if 'fileM' in implementedAPIPurpose: str += 'M'	
	if 'fileE' in implementedAPIPurpose: str += 'E'
	
	str1 = ''
	if 'file' in childFunctionImplementedAPIPurpose:
		if 'h' in childFunctionImplementedAPIPurpose['file']: str1 += 'h'
		if 'r' in childFunctionImplementedAPIPurpose['file']: str1 += 'r'
		if 'w' in childFunctionImplementedAPIPurpose['file']: str1 += 'w'
		if 'd' in childFunctionImplementedAPIPurpose['file']: str1 += 'd'
		if 'c' in childFunctionImplementedAPIPurpose['file']: str1 += 'c'
		if 'm' in childFunctionImplementedAPIPurpose['file']: str1 += 'm'
		if 'e' in childFunctionImplementedAPIPurpose['file']: str1 += 'e'
	
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'file'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
	
	str = ''
	if 'strB' in implementedAPIPurpose: str += 'B'
	if 'strC' in implementedAPIPurpose: str += 'C'
	
	str1 = ''
	if 'str' in childFunctionImplementedAPIPurpose:
		if 'b' in childFunctionImplementedAPIPurpose['str']: str1 += 'b'
		if 'c' in childFunctionImplementedAPIPurpose['str']: str1 += 'c'
		
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'str'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
		
	str = ''
	if 'servH' in implementedAPIPurpose: str += 'H'
	if 'servC' in implementedAPIPurpose: str += 'C'
	if 'servD' in implementedAPIPurpose: str += 'D'
	if 'servS' in implementedAPIPurpose: str += 'S'
	if 'servR' in implementedAPIPurpose: str += 'R'
	if 'servW' in implementedAPIPurpose: str += 'W'
	
	str1 = ''
	if 'serv' in childFunctionImplementedAPIPurpose:
		if 'h' in childFunctionImplementedAPIPurpose['serv']: str1 += 'h'
		if 'c' in childFunctionImplementedAPIPurpose['serv']: str1 += 'c'
		if 'd' in childFunctionImplementedAPIPurpose['serv']: str1 += 'd'
		if 's' in childFunctionImplementedAPIPurpose['serv']: str1 += 's'
		if 'r' in childFunctionImplementedAPIPurpose['serv']: str1 += 'r'
		if 'w' in childFunctionImplementedAPIPurpose['serv']: str1 += 'w'
	
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'serv'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
		
	str = ''
	if 'threadC' in implementedAPIPurpose: str += 'C'
	if 'threadO' in implementedAPIPurpose: str += 'O'
	if 'threadS' in implementedAPIPurpose: str += 'S'
	if 'threadR' in implementedAPIPurpose: str += 'R'
	
	str1 = ''
	if 'thread' in childFunctionImplementedAPIPurpose:
		if 'c' in childFunctionImplementedAPIPurpose['thread']: str1 += 'c'
		if 'o' in childFunctionImplementedAPIPurpose['thread']: str1 += 'o'
		if 's' in childFunctionImplementedAPIPurpose['thread']: str1 += 's'
		if 'r' in childFunctionImplementedAPIPurpose['thread']: str1 += 'r'
	
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'thread'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
	
	str = ''
	if 'procH' in implementedAPIPurpose: str += 'H'
	if 'procE' in implementedAPIPurpose: str += 'E'
	if 'procC' in implementedAPIPurpose: str += 'C'
	if 'procT' in implementedAPIPurpose: str += 'T'
	if 'procR' in implementedAPIPurpose: str += 'R'
	if 'procW' in implementedAPIPurpose: str += 'W'
	
	str1 = ''
	if 'proc' in childFunctionImplementedAPIPurpose:
		if 'h' in childFunctionImplementedAPIPurpose['proc']: str1 += 'h'
		if 'e' in childFunctionImplementedAPIPurpose['proc']: str1 += 'e'
		if 'c' in childFunctionImplementedAPIPurpose['proc']: str1 += 'c'
		if 't' in childFunctionImplementedAPIPurpose['proc']: str1 += 't'
		if 'r' in childFunctionImplementedAPIPurpose['proc']: str1 += 'r'
		if 'w' in childFunctionImplementedAPIPurpose['proc']: str1 += 'w'
	
	if (len(str) > 0) or (len(str1) > 0):
		newFuncNamePurpose = newFuncNamePurpose + 'proc'
		if len(str) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str
		if len(str1) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + str1
		newFuncNamePurpose = newFuncNamePurpose + '__'
		
	if len(newFuncNamePurpose) > 0:
		finalFuncName = '{}{}xref_{:02d}'.format(CUSTOM_FUNC_PREFIX, newFuncNamePurpose, refToCount)
		
	else:
		finalFuncName = '{}{}{:X}__xref_{:02d}'.format(CUSTOM_FUNC_PREFIX, IDA_FUNC_PREFIX, funcEa, refToCount)
		
	return finalFuncName
	
if __name__ == '__main__':
	#Auto_Name_Function_Wrapper()
	pass

