// Answers one read-only query about the current program for a remote AI.
// Run by the device as a headless -postScript: HexeyTool.java <mode> [args...]
// Output is framed by "=== HEXEY <mode> ..." and "=== END ===" so the caller
// can drop Ghidra's own log lines. Nothing here changes the program.
//@category Hexey
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class HexeyTool extends GhidraScript {
    private static final int MAX_LINES = 2000;
    private int lines = 0;
    private boolean truncated = false;

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String mode = a.length > 0 ? a[0] : "info";
        String a1 = a.length > 1 ? a[1] : "";
        String a2 = a.length > 2 ? a[2] : "";
        System.out.println("=== HEXEY " + mode + " " + a1 + (a2.isEmpty() ? "" : " " + a2) + " ===");
        try {
            switch (mode) {
                case "list" -> list(a1);
                case "decompile" -> decompile(a1);
                case "strings" -> strings(a1);
                case "xrefs" -> xrefs(a1);
                case "disasm" -> disasm(a1, intArg(a2, 200, 2000));
                case "bytes" -> bytes(a1, intArg(a2, 256, 4096));
                case "imports" -> imports(a1);
                case "exports" -> exports(a1);
                case "function" -> function(a1);
                case "memmap" -> memmap();
                case "search_bytes" -> searchBytes(a1, intArg(a2, 100, 1000));
                case "symbols" -> symbols(a1);
                case "callgraph" -> callgraph(a1, intArg(a2, 2, 4));
                case "cfg" -> cfg(a1);
                case "pcode" -> pcode(a1);
                case "high_pcode" -> highPcode(a1);
                case "datatypes" -> datatypes(a1);
                case "variables" -> variables(a1);
                case "refs_from" -> refsFrom(a1);
                case "calls" -> calls(a1);
                case "constants" -> constants(a1);
                case "tokens" -> tokens(a1);
                case "report" -> report(intArg(a1, 300, 2000));
                default -> info();
            }
        } catch (StopOutput stop) {
            // line cap reached; noted below
        }
        if (truncated) System.out.println("... (output capped at " + MAX_LINES + " lines; narrow the query)");
        System.out.println("=== END ===");
    }

    private static class StopOutput extends RuntimeException {
        StopOutput() { super(null, null, false, false); }
    }

    private void out(String s) {
        if (lines >= MAX_LINES) { truncated = true; throw new StopOutput(); }
        lines += 1;
        System.out.println(s);
    }

    private void err(String s) { System.out.println("ERROR: " + s); }

    private int intArg(String s, int def, int max) {
        try { return Math.max(1, Math.min(max, Integer.parseInt(s.trim()))); } catch (Exception e) { return def; }
    }

    private Address addr(String s) {
        if (s == null || s.isBlank()) return null;
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        try { return toAddr(t); } catch (Exception e) { return null; }
    }

    private Function findFunc(String nameOrAddr) {
        if (nameOrAddr == null || nameOrAddr.isBlank()) return null;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(nameOrAddr)) return f;
        }
        Address a = addr(nameOrAddr);
        return a != null ? getFunctionContaining(a) : null;
    }

    private Function needFunc(String target) {
        Function f = findFunc(target);
        if (f == null) err("function not found: " + target);
        return f;
    }

    private String hex(byte[] b, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i] & 0xff)).append(i + 1 < n ? " " : "");
        return sb.toString();
    }

    // ---- program ----

    private void info() {
        out("name: " + currentProgram.getName());
        out("format: " + currentProgram.getExecutableFormat());
        out("language: " + currentProgram.getLanguageID());
        out("compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        out("image base: " + currentProgram.getImageBase());
        out("functions: " + currentProgram.getFunctionManager().getFunctionCount());
        out("md5: " + currentProgram.getExecutableMD5());
    }

    private void memmap() {
        out("name  start  end  size  perms  initialized");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            String perms = (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-");
            out(b.getName() + "  " + b.getStart() + "  " + b.getEnd() + "  " + b.getSize() + "  " + perms + "  " + b.isInitialized());
        }
    }

    private void imports(String filter) {
        ExternalManager em = currentProgram.getExternalManager();
        for (String lib : em.getExternalLibraryNames()) {
            Iterator<ExternalLocation> it = em.getExternalLocations(lib);
            while (it.hasNext()) {
                ExternalLocation loc = it.next();
                String name = loc.getLabel();
                if (!filter.isEmpty() && !(lib + "!" + name).toLowerCase().contains(filter.toLowerCase())) continue;
                Address thunk = null;
                Symbol s = loc.getSymbol();
                if (s != null) {
                    for (Reference r : getReferencesTo(s.getAddress())) { thunk = r.getFromAddress(); break; }
                }
                out(lib + "!" + name + (thunk != null ? "  ref " + thunk : ""));
            }
        }
    }

    private void exports(String filter) {
        Iterator<Address> it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (it.hasNext()) {
            Address a = it.next();
            Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
            String name = s != null ? s.getName() : "-";
            if (!filter.isEmpty() && !name.toLowerCase().contains(filter.toLowerCase())) continue;
            out(a + "  " + name);
        }
    }

    private void symbols(String query) {
        SymbolTable st = currentProgram.getSymbolTable();
        Address a = addr(query);
        if (a != null) {
            for (Symbol s : st.getSymbols(a)) out(s.getAddress() + "  " + s.getSymbolType() + "  " + s.getName(true));
        }
        if (query.isEmpty() && a == null) { err("a name or address is required"); return; }
        String q = query.toLowerCase();
        SymbolIterator it = st.getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getName(true).toLowerCase().contains(q)) out(s.getAddress() + "  " + s.getSymbolType() + "  " + s.getName(true));
        }
    }

    // ---- functions ----

    private void list(String filter) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (!filter.isEmpty() && !f.getName().toLowerCase().contains(filter.toLowerCase())) continue;
            out(f.getEntryPoint() + "  " + f.getBody().getNumAddresses() + "  " + f.getName());
        }
    }

    private void function(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        out("name: " + f.getName(true));
        out("entry: " + f.getEntryPoint());
        out("body: " + f.getBody().getMinAddress() + " - " + f.getBody().getMaxAddress() + " (" + f.getBody().getNumAddresses() + " bytes)");
        out("signature: " + f.getSignature().getPrototypeString());
        out("calling convention: " + f.getCallingConventionName());
        out("return: " + f.getReturnType().getDisplayName() + "  " + f.getReturn().getVariableStorage());
        for (Parameter p : f.getParameters()) out("param " + p.getOrdinal() + ": " + p.getDataType().getDisplayName() + " " + p.getName() + "  " + p.getVariableStorage());
        out("varargs: " + f.hasVarArgs() + "  thunk: " + f.isThunk() + "  external: " + f.isExternal());
        out("stack frame size: " + f.getStackFrame().getFrameSize());
        out("callers: " + f.getCallingFunctions(monitor).size() + "  callees: " + f.getCalledFunctions(monitor).size());
    }

    private void calls(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (!ins.getFlowType().isCall()) continue;
            for (Reference r : ins.getReferencesFrom()) {
                if (!r.getReferenceType().isCall()) continue;
                Function to = getFunctionAt(r.getToAddress());
                if (to == null) to = getFunctionContaining(r.getToAddress());
                out(ins.getAddress() + "  -> " + r.getToAddress() + "  " + (to != null ? to.getName(true) : "?"));
            }
        }
    }

    private void callgraph(String target, int depth) {
        Function root = needFunc(target);
        if (root == null) return;
        out("callers of " + root.getName() + ":");
        walk(root, depth, false, "  ", new HashSet<>());
        out("callees of " + root.getName() + ":");
        walk(root, depth, true, "  ", new HashSet<>());
    }

    private void walk(Function f, int depth, boolean down, String indent, Set<Function> seen) {
        if (depth <= 0 || !seen.add(f)) return;
        Set<Function> next = down ? f.getCalledFunctions(monitor) : f.getCallingFunctions(monitor);
        for (Function g : next) {
            out(indent + g.getEntryPoint() + "  " + g.getName(true) + (seen.contains(g) ? "  (seen)" : ""));
            walk(g, depth - 1, down, indent + "  ", seen);
        }
    }

    private void cfg(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        BasicBlockModel model = new BasicBlockModel(currentProgram);
        try {
            CodeBlockIterator it = model.getCodeBlocksContaining(f.getBody(), monitor);
            while (it.hasNext()) {
                CodeBlock b = it.next();
                StringBuilder succ = new StringBuilder();
                CodeBlockReferenceIterator d = b.getDestinations(monitor);
                while (d.hasNext()) {
                    CodeBlockReference r = d.next();
                    succ.append(" ").append(r.getDestinationAddress()).append("(").append(r.getFlowType()).append(")");
                }
                out(b.getMinAddress() + " - " + b.getMaxAddress() + "  ->" + (succ.length() == 0 ? " (exit)" : succ));
            }
        } catch (Exception e) {
            err("could not build the control flow graph: " + e.getMessage());
        }
    }

    // ---- instructions and bytes ----

    private void disasm(String target, int max) {
        Function f = findFunc(target);
        Address start = f != null ? f.getEntryPoint() : addr(target);
        if (start == null) { err("not a function or address: " + target); return; }
        AddressSetView body = f != null ? f.getBody() : null;
        InstructionIterator it = body != null
            ? currentProgram.getListing().getInstructions(body, true)
            : currentProgram.getListing().getInstructions(start, true);
        int n = 0;
        while (it.hasNext() && n < max) {
            Instruction ins = it.next();
            byte[] b;
            try { b = ins.getBytes(); } catch (Exception e) { b = new byte[0]; }
            out(ins.getAddress() + "  " + String.format("%-24s", hex(b, b.length)) + "  " + ins);
            n++;
        }
        if (n == 0) err("no instructions at " + start + " (data, or not disassembled)");
        else if (it.hasNext()) out("... (stopped after " + max + " instructions; pass a larger count)");
    }

    private void bytes(String at, int len) {
        Address a = addr(at);
        if (a == null) { err("not an address: " + at); return; }
        byte[] buf = new byte[len];
        int got;
        try { got = currentProgram.getMemory().getBytes(a, buf); } catch (Exception e) { err("cannot read " + a + ": " + e.getMessage()); return; }
        for (int off = 0; off < got; off += 16) {
            int n = Math.min(16, got - off);
            byte[] row = new byte[n];
            System.arraycopy(buf, off, row, 0, n);
            StringBuilder ascii = new StringBuilder();
            for (byte x : row) { int c = x & 0xff; ascii.append(c >= 32 && c < 127 ? (char) c : '.'); }
            out(a.add(off) + "  " + String.format("%-47s", hex(row, n)) + "  " + ascii);
        }
    }

    private void searchBytes(String pattern, int max) {
        String[] parts = pattern.trim().split("\\s+");
        if (pattern.isBlank() || parts.length > 256) { err("pattern must be 1 to 256 hex bytes, e.g. \"48 8b ?? 05\""); return; }
        byte[] val = new byte[parts.length];
        byte[] mask = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].equals("??") || parts[i].equals("?")) { val[i] = 0; mask[i] = 0; continue; }
            try { val[i] = (byte) Integer.parseInt(parts[i], 16); mask[i] = (byte) 0xff; }
            catch (Exception e) { err("not a hex byte: " + parts[i]); return; }
        }
        Memory mem = currentProgram.getMemory();
        Address cur = mem.getMinAddress();
        int n = 0;
        while (cur != null && n < max && !monitor.isCancelled()) {
            Address hit = mem.findBytes(cur, val, mask, true, monitor);
            if (hit == null) break;
            Function f = getFunctionContaining(hit);
            MemoryBlock b = mem.getBlock(hit);
            out(hit + "  " + (b != null ? b.getName() : "-") + "  " + (f != null ? f.getName(true) : "-"));
            n++;
            cur = hit.next();
        }
        if (n == 0) out("(no matches)");
    }

    private void constants(String value) {
        long want;
        try {
            String v = value.trim().toLowerCase();
            want = v.startsWith("0x") ? Long.parseUnsignedLong(v.substring(2), 16) : Long.parseLong(v);
        } catch (Exception e) { err("value must be a number, decimal or 0x hex: " + value); return; }
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            boolean hit = false;
            for (int i = 0; i < ins.getNumOperands() && !hit; i++) {
                for (Object o : ins.getOpObjects(i)) {
                    if (o instanceof Scalar s && (s.getUnsignedValue() == want || s.getSignedValue() == want)) { hit = true; break; }
                }
            }
            if (hit) {
                Function f = getFunctionContaining(ins.getAddress());
                out(ins.getAddress() + "  " + ins + "  " + (f != null ? f.getName(true) : "-"));
            }
        }
    }

    private void pcode(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            out(ins.getAddress() + "  " + ins);
            for (PcodeOp op : ins.getPcode()) out("    " + op);
        }
    }

    // ---- references ----

    private void xrefs(String target) {
        Function f = findFunc(target);
        Address a = f != null ? f.getEntryPoint() : addr(target);
        if (a == null) { err("not found: " + target); return; }
        for (Reference ref : getReferencesTo(a)) {
            Function from = getFunctionContaining(ref.getFromAddress());
            out(ref.getFromAddress() + "  " + ref.getReferenceType() + "  " + (from != null ? from.getName(true) : "-"));
        }
    }

    private void refsFrom(String target) {
        Function f = findFunc(target);
        List<Address> from = new ArrayList<>();
        if (f != null) {
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) from.add(it.next().getAddress());
        } else {
            Address a = addr(target);
            if (a == null) { err("not a function or address: " + target); return; }
            from.add(a);
        }
        for (Address a : from) {
            for (Reference r : getReferencesFrom(a)) {
                Function to = getFunctionAt(r.getToAddress());
                Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                String name = to != null ? to.getName(true) : s != null ? s.getName(true) : "-";
                out(a + "  -> " + r.getToAddress() + "  " + r.getReferenceType() + "  " + name);
            }
        }
    }

    // ---- data ----

    private void strings(String filter) {
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data data = it.next();
            if (!data.hasStringValue()) continue;
            String v = String.valueOf(data.getValue());
            if (!filter.isEmpty() && !v.toLowerCase().contains(filter.toLowerCase())) continue;
            out(data.getAddress() + "  " + v.replace("\n", "\\n"));
        }
    }

    private void datatypes(String filter) {
        List<DataType> found = new ArrayList<>();
        Iterator<DataType> it = currentProgram.getDataTypeManager().getAllDataTypes();
        while (it.hasNext()) {
            DataType dt = it.next();
            if (!(dt instanceof Composite || dt instanceof Enum)) continue;
            if (!filter.isEmpty() && !dt.getName().toLowerCase().contains(filter.toLowerCase())) continue;
            found.add(dt);
        }
        if (found.size() == 1 || (!filter.isEmpty() && found.stream().anyMatch(d -> d.getName().equals(filter)))) {
            DataType dt = found.size() == 1 ? found.get(0) : found.stream().filter(d -> d.getName().equals(filter)).findFirst().get();
            describe(dt);
            return;
        }
        for (DataType dt : found) out(kind(dt) + "  " + dt.getPathName() + "  " + dt.getLength() + " bytes");
        if (found.isEmpty()) out("(no structures, unions or enums" + (filter.isEmpty() ? "" : " matching " + filter) + ")");
    }

    private String kind(DataType dt) {
        return dt instanceof Structure ? "struct" : dt instanceof Union ? "union" : dt instanceof Enum ? "enum" : "type";
    }

    private void describe(DataType dt) {
        out(kind(dt) + " " + dt.getPathName() + "  (" + dt.getLength() + " bytes)");
        if (dt instanceof Composite c) {
            for (DataTypeComponent m : c.getComponents()) {
                out("  +" + String.format("0x%x", m.getOffset()) + "  " + m.getDataType().getDisplayName() + "  " + (m.getFieldName() != null ? m.getFieldName() : "(unnamed)") + "  " + m.getLength());
            }
        } else if (dt instanceof Enum e) {
            for (String n : e.getNames()) out("  " + n + " = " + e.getValue(n));
        }
    }

    // ---- report ----

    private static String js(Object o) {
        String s = String.valueOf(o);
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> { if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c); }
            }
        }
        return b.append('"').toString();
    }

    /** One JSON document summarising the program, printed as a single line. */
    private void report(int maxItems) {
        StringBuilder j = new StringBuilder("{");
        j.append("\"name\":").append(js(currentProgram.getName()));
        j.append(",\"format\":").append(js(currentProgram.getExecutableFormat()));
        j.append(",\"language\":").append(js(currentProgram.getLanguageID()));
        j.append(",\"compiler\":").append(js(currentProgram.getCompilerSpec().getCompilerSpecID()));
        j.append(",\"imageBase\":").append(js(currentProgram.getImageBase()));
        j.append(",\"md5\":").append(js(currentProgram.getExecutableMD5()));
        j.append(",\"functionCount\":").append(currentProgram.getFunctionManager().getFunctionCount());
        j.append(",\"memory\":[");
        boolean first = true;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            String perms = (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-");
            j.append(first ? "" : ",").append("{\"name\":").append(js(b.getName())).append(",\"start\":").append(js(b.getStart()))
                .append(",\"size\":").append(b.getSize()).append(",\"perms\":").append(js(perms)).append('}');
            first = false;
        }
        j.append("],\"imports\":[");
        first = true;
        int n = 0;
        ExternalManager em = currentProgram.getExternalManager();
        for (String lib : em.getExternalLibraryNames()) {
            Iterator<ExternalLocation> it = em.getExternalLocations(lib);
            while (it.hasNext() && n < maxItems) {
                j.append(first ? "" : ",").append(js(lib + "!" + it.next().getLabel()));
                first = false;
                n++;
            }
        }
        j.append("],\"exports\":[");
        first = true;
        n = 0;
        Iterator<Address> ex = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (ex.hasNext() && n++ < maxItems) {
            Address a = ex.next();
            Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
            j.append(first ? "" : ",").append("{\"address\":").append(js(a)).append(",\"name\":").append(js(s != null ? s.getName() : "-")).append('}');
            first = false;
        }
        j.append("],\"functions\":[");
        first = true;
        n = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (n++ >= maxItems) break;
            j.append(first ? "" : ",").append("{\"address\":").append(js(f.getEntryPoint())).append(",\"name\":").append(js(f.getName(true)))
                .append(",\"size\":").append(f.getBody().getNumAddresses()).append('}');
            first = false;
        }
        j.append("],\"strings\":[");
        first = true;
        n = 0;
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext() && n < maxItems) {
            Data data = it.next();
            if (!data.hasStringValue()) continue;
            j.append(first ? "" : ",").append("{\"address\":").append(js(data.getAddress())).append(",\"value\":").append(js(data.getValue())).append('}');
            first = false;
            n++;
        }
        j.append("]}");
        System.out.println(j);
    }

    // ---- decompiler ----

    private DecompileResults decompileResults(Function f) {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try {
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (!r.decompileCompleted()) { err(r.getErrorMessage()); return null; }
            return r;
        } finally {
            d.dispose();
        }
    }

    private void decompile(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        DecompileResults r = decompileResults(f);
        if (r != null) for (String line : r.getDecompiledFunction().getC().split("\n")) out(line);
    }

    private void highPcode(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        DecompileResults r = decompileResults(f);
        if (r == null) return;
        HighFunction hf = r.getHighFunction();
        Iterator<PcodeOpAST> it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOpAST op = it.next();
            out((op.getSeqnum() != null ? op.getSeqnum().getTarget() : "-") + "  " + op);
        }
    }

    private void variables(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        out("declared in the function:");
        for (Variable v : f.getAllVariables()) out("  " + v.getDataType().getDisplayName() + " " + v.getName() + "  " + v.getVariableStorage() + (v instanceof Parameter ? "  (param)" : ""));
        DecompileResults r = decompileResults(f);
        if (r == null) return;
        out("seen by the decompiler:");
        Iterator<HighSymbol> it = r.getHighFunction().getLocalSymbolMap().getSymbols();
        while (it.hasNext()) {
            HighSymbol s = it.next();
            out("  " + s.getDataType().getDisplayName() + " " + s.getName() + "  " + s.getStorage() + (s.isParameter() ? "  (param)" : ""));
        }
    }

    private void tokens(String target) {
        Function f = needFunc(target);
        if (f == null) return;
        DecompileResults r = decompileResults(f);
        if (r == null) return;
        ClangTokenGroup root = r.getCCodeMarkup();
        ArrayDeque<ClangNode> stack = new ArrayDeque<>();
        stack.push(root);
        List<ClangToken> toks = new ArrayList<>();
        // Depth-first, children in order.
        while (!stack.isEmpty()) {
            ClangNode n = stack.pop();
            if (n instanceof ClangToken t) { toks.add(t); continue; }
            for (int i = n.numChildren() - 1; i >= 0; i--) stack.push(n.Child(i));
        }
        for (ClangToken t : toks) {
            String txt = t.getText();
            if (txt == null || txt.isBlank()) continue;
            Address a = t.getMinAddress();
            out((a != null ? a.toString() : "-") + "  " + t.getClass().getSimpleName().replace("Clang", "").replace("Token", "") + "  " + txt);
        }
    }
}
