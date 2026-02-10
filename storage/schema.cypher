CREATE CONSTRAINT function_name IF NOT EXISTS FOR (f:Function) REQUIRE f.addr IS UNIQUE;
CREATE INDEX bb_addr IF NOT EXISTS FOR (b:BasicBlock) ON (b.addr);
CREATE INDEX instr_addr IF NOT EXISTS FOR (i:Instruction) ON (i.addr);
