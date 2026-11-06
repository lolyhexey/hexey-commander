// Applies one edit to the current program for a remote AI, inside the
// script's transaction, and saves the project. The device backs the project
// up before running this, so every edit can be undone.
// Run as a headless -postScript: HexeyEdit.java <mode> [args...]
//@category Hexey
import java.io.File;
import java.util.Iterator;
import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.exporter.Exporter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public class HexeyEdit extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String mode = a.length > 0 ? a[0] : "";
        String a1 = a.length > 1 ? a[1] : "";
        String a2 = a.length > 2 ? a[2] : "";
        String a3 = a.length > 3 ? a[3] : "";
        System.out.println("=== HEXEY " + mode + " " + a1 + " ===");
        try {
            switch (mode) {
                case "rename_function" -> renameFunction(a1, a2);
                case "rename_variable" -> renameVariable(a1, a2, a3);
                case "set_comment" -> setComment(a1, a2, a3);
                case "set_signature" -> setSignature(a1, a2);
                case "create_structure" -> createStructure(a1);
                case "apply_data_type" -> applyDataType(a1, a2);
                case "patch_bytes" -> patchBytes(a1, a2);
                case "export" -> export(a1, a2);
                default -> fail("unknown edit: " + mode);
            }
        } catch (EditFailed e) {
            System.out.println("ERROR: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        System.out.println("=== END ===");
    }

    private static class EditFailed extends RuntimeException {
        EditFailed(String m) { super(m, null, false, false); }
    }

    private void fail(String m) { throw new EditFailed(m); }

    private void ok(String s) { System.out.println("OK: " + s); }

    private Address addr(String s) {
        if (s == null || s.isBlank()) fail("an address is required");
        String t = s.trim();
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2);
        Address a = null;
        try { a = toAddr(t); } catch (Exception e) { a = null; }
        if (a == null) fail("not an address: " + s);
        return a;
    }

    private Function func(String nameOrAddr) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(nameOrAddr)) return f;
        }
        Function f = null;
        try { f = getFunctionContaining(addr(nameOrAddr)); } catch (EditFailed e) { f = null; }
        if (f == null) fail("function not found: " + nameOrAddr);
        return f;
    }

    private void renameFunction(String target, String newName) throws Exception {
        if (newName.isBlank()) fail("a new name is required");
        Function f = func(target);
        String old = f.getName();
        f.setName(newName.trim(), SourceType.USER_DEFINED);
        ok("renamed function " + old + " -> " + f.getName() + " at " + f.getEntryPoint());
    }

    private void renameVariable(String target, String oldName, String newName) throws Exception {
        if (oldName.isBlank() || newName.isBlank()) fail("the variable's current name and a new name are required");
        Function f = func(target);
        for (Variable v : f.getAllVariables()) {
            if (v.getName().equals(oldName)) {
                v.setName(newName.trim(), SourceType.USER_DEFINED);
                ok("renamed variable " + oldName + " -> " + newName.trim() + " in " + f.getName());
                return;
            }
        }
        // Not declared yet: a name the decompiler invented. Commit it under the new name.
        DecompInterface d = new DecompInterface();
        try {
            d.openProgram(currentProgram);
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            if (!r.decompileCompleted()) fail("decompiler: " + r.getErrorMessage());
            Iterator<HighSymbol> it = r.getHighFunction().getLocalSymbolMap().getSymbols();
            while (it.hasNext()) {
                HighSymbol s = it.next();
                if (s.getName().equals(oldName)) {
                    HighFunctionDBUtil.updateDBVariable(s, newName.trim(), null, SourceType.USER_DEFINED);
                    ok("renamed variable " + oldName + " -> " + newName.trim() + " in " + f.getName());
                    return;
                }
            }
        } finally {
            d.dispose();
        }
        fail("no variable named " + oldName + " in " + f.getName());
    }

    private void setComment(String at, String kind, String comment) {
        Address a = addr(at);
        int type = switch (kind.toLowerCase()) {
            case "eol", "" -> CodeUnit.EOL_COMMENT;
            case "pre" -> CodeUnit.PRE_COMMENT;
            case "post" -> CodeUnit.POST_COMMENT;
            case "plate" -> CodeUnit.PLATE_COMMENT;
            case "repeatable" -> CodeUnit.REPEATABLE_COMMENT;
            default -> { fail("kind must be eol, pre, post, plate or repeatable"); yield 0; }
        };
        currentProgram.getListing().setComment(a, type, comment.isEmpty() ? null : comment);
        ok((comment.isEmpty() ? "cleared " : "set ") + (kind.isEmpty() ? "eol" : kind) + " comment at " + a);
    }

    private void setSignature(String target, String signature) throws Exception {
        if (signature.isBlank()) fail("a C signature is required, e.g. \"int parse(char *buf, int len)\"");
        Function f = func(target);
        // CParserUtils.parseSignature needs a GUI service; parse the prototype as a C declaration instead.
        String decl = signature.trim().endsWith(";") ? signature.trim() : signature.trim() + ";";
        DataType parsed = new CParser(currentProgram.getDataTypeManager(), false, null).parse(decl);
        if (!(parsed instanceof ghidra.program.model.data.FunctionDefinition def)) { fail("could not parse the signature: " + signature); return; }
        FunctionDefinitionDataType sig = new FunctionDefinitionDataType(def, currentProgram.getDataTypeManager());
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED);
        if (!cmd.applyTo(currentProgram, monitor)) fail(cmd.getStatusMsg());
        ok("signature of " + f.getEntryPoint() + " is now " + f.getSignature().getPrototypeString());
    }

    private void createStructure(String definition) throws Exception {
        if (definition.isBlank()) fail("a C definition is required, e.g. \"struct Header { int magic; short count; char name[16]; };\"");
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        CParser parser = new CParser(dtm, true, null);
        DataType parsed = parser.parse(definition);
        if (parsed == null) fail("could not parse the definition");
        DataType added = dtm.addDataType(parsed, DataTypeConflictHandler.REPLACE_HANDLER);
        ok("defined " + added.getPathName() + " (" + added.getLength() + " bytes)");
    }

    private DataType findType(String name) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        DataTypeParser p = new DataTypeParser(dtm, dtm, null, AllowedDataTypes.ALL);
        try {
            DataType dt = p.parse(name.trim());
            if (dt != null) return dt;
        } catch (Exception ignored) {
            // fall through to a by-name search
        }
        java.util.ArrayList<DataType> found = new java.util.ArrayList<>();
        dtm.findDataTypes(name.trim(), found);
        if (found.isEmpty()) fail("no data type named " + name);
        return found.get(0);
    }

    private void applyDataType(String at, String typeName) throws Exception {
        if (typeName.isBlank()) fail("a data type name is required, e.g. \"dword\", \"char[16]\", \"IMAGE_DOS_HEADER\"");
        Address a = addr(at);
        DataType dt = findType(typeName);
        if (currentProgram.getListing().getInstructionContaining(a) != null) fail(a + " is code; refusing to turn instructions into data");
        int len = Math.max(1, dt.getLength());
        clearListing(a, a.add(len - 1));
        createData(a, dt);
        ok("applied " + dt.getDisplayName() + " at " + a + " (" + len + " bytes)");
    }

    private void patchBytes(String at, String hexBytes) throws Exception {
        Address a = addr(at);
        String[] parts = hexBytes.trim().split("\\s+");
        if (hexBytes.isBlank() || parts.length > 4096) fail("bytes must be 1 to 4096 hex bytes, e.g. \"90 90\"");
        byte[] b = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try { b[i] = (byte) Integer.parseInt(parts[i], 16); } catch (Exception e) { fail("not a hex byte: " + parts[i]); }
        }
        Address end = a.add(b.length - 1);
        boolean wasCode = currentProgram.getListing().getInstructionContaining(a) != null;
        byte[] before = new byte[b.length];
        currentProgram.getMemory().getBytes(a, before);
        clearListing(a, end);
        currentProgram.getMemory().setBytes(a, b);
        if (wasCode) disassemble(a);
        StringBuilder old = new StringBuilder();
        for (byte x : before) old.append(String.format("%02x ", x & 0xff));
        ok("patched " + b.length + " bytes at " + a + " (was " + old.toString().trim() + ")" + (wasCode ? "; re-disassembled" : ""));
        if (wasCode) {
            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            if (ins != null) ok("now: " + a + "  " + ins);
        }
    }

    private void export(String format, String outPath) throws Exception {
        String want = switch (format.toLowerCase()) {
            case "c" -> "C/C++";
            case "xml" -> "XML";
            case "ascii" -> "Ascii";
            case "original", "binary" -> "Original File";
            case "raw" -> "Raw Bytes";
            default -> { fail("format must be c, xml, ascii, original or raw"); yield ""; }
        };
        Exporter exporter = null;
        List<Exporter> all = ClassSearcher.getInstances(Exporter.class);
        for (Exporter e : all) if (e.getName().equalsIgnoreCase(want)) exporter = e;
        if (exporter == null) {
            StringBuilder names = new StringBuilder();
            for (Exporter e : all) names.append(e.getName()).append(", ");
            fail("this Ghidra has no \"" + want + "\" exporter (has: " + names + ")");
        }
        File out = new File(outPath);
        if (!exporter.export(out, currentProgram, null, monitor)) fail("export failed");
        ok("exported " + want + " to " + out.getAbsolutePath() + " (" + out.length() + " bytes)");
    }
}
