from idc import *
from idautils import *
import idaapi

class aan_highlight_instructions_t(idaapi.plugin_t):
  flags = idaapi.PLUGIN_KEEP
  comment = ''
  help = ''
  wanted_name = 'aan_Highlight_Instructions'
  wanted_hotkey = 'ctrl-shift-h'
  
  def init(self):
    return idaapi.PLUGIN_KEEP
    
  def run(self):
    aan_Highlight_Instructions()
    
  def term(self):
    pass
    
def PLUGIN_ENTRY():
  return aan_highlight_instructions_t()
  
def aan_Highlight_Instructions():
  CALL_COLOR = 0x000000 # black
  STR_OPERATION_COLOR = 0x005500 # forest green
  BUFFER_COLOR = 0x5a4b27
  ENCRYPTION_COLOR = 0x62086c
  ZERO_OUT_COLOR = 0x656565
  DEFAULT_COLOR = 0xffffffff
  
  ea = ScreenEA()
  segStartEA = SegStart(ea)
  segEndEA = SegEnd(ea)
  for currentEA in Heads(segStartEA, segEndEA):
    currentMnem = GetMnem(currentEA)
    currentColor = GetColor(currentEA, CIC_ITEM)
    
    if currentMnem == 'call':
      changeColor = CALL_COLOR if currentColor == DEFAULT_COLOR else DEFAULT_COLOR
      SetColor(currentEA, CIC_ITEM, changeColor)
      
    if currentMnem == 'scas' or currentMnem == 'movs' or currentMnem == 'stos':
      changeColor = STR_OPERATION_COLOR if currentColor == DEFAULT_COLOR else DEFAULT_COLOR
      SetColor(currentEA, CIC_ITEM, changeColor)
      
    if currentMnem == 'xor' and (GetOpnd(currentEA,0) == GetOpnd(currentEA, 1)):
      changeColor = ZERO_OUT_COLOR if currentColor == DEFAULT_COLOR else DEFAULT_COLOR
      SetColor(currentEA, CIC_ITEM, changeColor)
      
    if currentMnem == 'lea':
      changeColor = BUFFER_COLOR if currentColor == DEFAULT_COLOR else DEFAULT_COLOR
      SetColor(currentEA, CIC_ITEM, changeColor)
      
    if currentMnem == 'xor' and (GetOpnd(currentEA,0) != GetOpnd(currentEA, 1)):
      changeColor = ENCRYPTION_COLOR if currentColor == DEFAULT_COLOR else DEFAULT_COLOR
      SetColor(currentEA, CIC_ITEM, changeColor)
      
if __name__ == '__main__':
  pass
  #aan_Highlight_Instructions()
