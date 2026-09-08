package digbridge;

import de.neemann.digital.core.element.ElementAttributes;
import de.neemann.digital.core.element.ElementTypeDescription;
import de.neemann.digital.core.element.Key;
import de.neemann.digital.draw.elements.Circuit;
import de.neemann.digital.draw.elements.Pin;
import de.neemann.digital.draw.elements.Pins;
import de.neemann.digital.draw.elements.VisualElement;
import de.neemann.digital.draw.library.ElementLibrary;
import de.neemann.digital.draw.model.Net;
import de.neemann.digital.draw.model.NetList;
import de.neemann.digital.draw.shapes.ShapeFactory;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DigNetlist -- dump a Digital .dig circuit as a JSON netlist.
 *
 *   java -cp Digital.jar:digbridge.jar digbridge.DigNetlist circuit.dig out.json
 *
 * WHY THIS IS JAVA AND NOT PYTHON
 * -------------------------------
 * A .dig file stores wires as bare coordinate pairs:
 *
 *     <wire><p1 x="200" y="280"/><p2 x="220" y="280"/></wire>
 *
 * There is no logical netlist in the file.  Recovering connectivity means
 * knowing where every component's pins sit, which depends on the component
 * type, its rotation, its bit width, its input count, and the shape rules
 * Digital uses to lay it out.  Reimplementing that in Python would mean
 * porting a large part of Digital's rendering code and keeping it in sync
 * with upstream forever.
 *
 * Digital already does this resolution internally.  NetList(Circuit) walks
 * the wires and pins and produces the nets; VisualElement.getPins(...) gives
 * each component's pins in the same coordinate space.  Calling those classes
 * costs ~200 lines and cannot drift from Digital's own semantics, because it
 * *is* Digital's own semantics.
 *
 * The output JSON is a flat, named netlist that Python can consume without
 * knowing anything about geometry.
 *
 * OUTPUT SHAPE
 * ------------
 * {
 *   "circuit": "subcell.dig",
 *   "components": [
 *     {"id": "c0", "type": "In",     "attrs": {"Label": "x", "Bits": "64"}},
 *     {"id": "c1", "type": "Splitter","attrs": {"Input Splitting": "64",
 *                                               "Output splitting": "4*16"}},
 *     {"id": "c2", "type": "sbox_present.dig", "attrs": {}}
 *   ],
 *   "nets": [
 *     {"id": "n0", "labels": ["x"],
 *      "pins": [{"component": "c0", "pin": "out", "dir": "output"},
 *               {"component": "c1", "pin": "in",  "dir": "input"}]}
 *   ]
 * }
 *
 * BUILD
 * -----
 *   javac -cp Digital.jar -d build src/digbridge/DigNetlist.java
 *   jar cf digbridge.jar -C build .
 *
 * Digital is GPLv3.  Anything linking against Digital.jar inherits that, so
 * this extractor must be GPLv3 too.  Keep it in its own repository, separate
 * from the Python side, so the Python half stays under whatever licence you
 * prefer -- it only ever reads the JSON.
 */
public final class DigNetlist {

    private DigNetlist() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: DigNetlist [--pins] <circuit.dig> "
                    + "[out.json]");
            System.err.println("  --pins  dump every pin with its coordinates "
                    + "and exit; used by the .dig generator to place wires "
                    + "without hard-coding Digital's shape geometry.");
            System.exit(2);
        }
        boolean pinsOnly = args[0].equals("--pins");
        if (pinsOnly) {
            args = java.util.Arrays.copyOfRange(args, 1, args.length);
        }
        File digFile = new File(args[0]);

        ElementLibrary library = new ElementLibrary();
        ShapeFactory shapeFactory = new ShapeFactory(library);
        // Custom subcircuits are resolved relative to the file's folder.
        library.setRootFilePath(digFile.getParentFile());

        Circuit circuit = Circuit.loadCircuit(digFile, shapeFactory);

        if (pinsOnly) {
            StringBuilder sb = new StringBuilder("[\n");
            List<VisualElement> els = circuit.getElements();
            boolean first = true;
            for (int i = 0; i < els.size(); i++) {
                VisualElement ve = els.get(i);
                ve.setShapeFactory(shapeFactory);
                for (Pin p : ve.getPins()) {
                    if (!first) {
                        sb.append(",\n");
                    }
                    first = false;
                    sb.append("  {\"component\": \"c").append(i)
                      .append("\", \"type\": ").append(json(
                              ve.getElementName()))
                      .append(", \"pin\": ").append(json(p.getName()))
                      .append(", \"dir\": ").append(json(String.valueOf(
                              p.getDirection())))
                      .append(", \"x\": ").append(p.getPos().x)
                      .append(", \"y\": ").append(p.getPos().y)
                      .append("}");
                }
            }
            sb.append("\n]\n");
            if (args.length >= 2) {
                try (PrintWriter w = new PrintWriter(args[1], "UTF-8")) {
                    w.print(sb);
                }
            } else {
                System.out.print(sb);
            }
            return;
        }

        NetList netList = new NetList(circuit);

        // Number the nets first so pins can reference them by id.
        Map<Net, String> netId = new HashMap<>();
        int netNum = 0;
        for (Net net : netList) {
            netId.put(net, "n" + netNum++);
        }

        // Walk components and resolve each pin to a net BY POSITION.
        //
        // VisualElement.getPins() builds fresh Pin objects on every call, so
        // the Pin instances held by the NetList are never the same objects we
        // see here -- keying a map on Pin identity silently yields empty nets.
        // NetList.getNetOfPos(Vector) is the supported lookup and is what the
        // rest of Digital uses.
        List<VisualElement> elements = circuit.getElements();
        Map<String, List<String>> netPins = new HashMap<>();
        StringBuilder comps = new StringBuilder();
        StringBuilder loose = new StringBuilder();

        for (int i = 0; i < elements.size(); i++) {
            VisualElement ve = elements.get(i);
            String id = "c" + i;
            ve.setShapeFactory(shapeFactory);

            for (Pin p : ve.getPins()) {
                Net net = netList.getNetOfPos(p.getPos());
                if (net == null) {
                    // Report it rather than dropping it: a pin the user meant
                    // to wire but missed is the most common circuit mistake,
                    // and it is invisible in the .dig file.
                    if (loose.length() > 0) {
                        loose.append(",\n");
                    }
                    loose.append("    {\"component\": \"").append(id)
                         .append("\", \"pin\": ").append(json(p.getName()))
                         .append(", \"dir\": ").append(json(String.valueOf(
                                 p.getDirection())))
                         .append(", \"x\": ").append(p.getPos().x)
                         .append(", \"y\": ").append(p.getPos().y)
                         .append("}");
                    continue;
                }
                String nid = netId.get(net);
                netPins.computeIfAbsent(nid, k -> new ArrayList<>())
                       .add("{\"component\": \"" + id + "\""
                            + ", \"pin\": " + json(p.getName())
                            + ", \"dir\": " + json(String.valueOf(
                                    p.getDirection()))
                            + "}");
            }

            if (comps.length() > 0) {
                comps.append(",\n");
            }
            comps.append("    {\"id\": \"").append(id).append("\"")
                 .append(", \"type\": ").append(json(ve.getElementName()))
                 .append(", \"attrs\": ")
                 .append(attrsToJson(ve.getElementAttributes(),
                                     keysOf(library, ve)))
                 .append("}");
        }

        StringBuilder nets = new StringBuilder();
        for (Net net : netList) {
            String nid = netId.get(net);
            StringBuilder labels = new StringBuilder();
            for (String l : net.getLabels()) {
                if (labels.length() > 0) {
                    labels.append(", ");
                }
                labels.append(json(l));
            }
            List<String> pins = netPins.getOrDefault(nid, new ArrayList<>());
            if (nets.length() > 0) {
                nets.append(",\n");
            }
            nets.append("    {\"id\": \"").append(nid).append("\"")
                .append(", \"labels\": [").append(labels).append("]")
                .append(", \"pins\": [")
                .append(String.join(", ", pins)).append("]}");
        }

        String out = "{\n"
                + "  \"circuit\": " + json(digFile.getName()) + ",\n"
                + "  \"components\": [\n" + comps + "\n  ],\n"
                + "  \"nets\": [\n" + nets + "\n  ],\n"
                + "  \"unconnected\": [\n" + loose + "\n  ]\n"
                + "}\n";

        if (args.length >= 2) {
            try (PrintWriter w = new PrintWriter(args[1], "UTF-8")) {
                w.print(out);
            }
            System.err.println("wrote " + args[1]);
        } else {
            System.out.print(out);
        }
    }

    /**
     * Attributes are the only place the cipher's parameters live: the S-box
     * table sits in a ROM's "Data", the rotation amount in a Splitter's bit
     * ranges, the word size in "Bits".  Dump them all as strings and let the
     * Python side decide what to parse.
     */
    private static String attrsToJson(ElementAttributes attr,
                                      java.util.List<Key> keys) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Key key : keys) {
            if (!attr.contains(key)) {
                continue;
            }
            Object v = attr.get(key);
            if (v == null) {
                continue;
            }
            // A ROM's lookup table arrives as a DataField whose toString() is
            // an object hash.  Expand it: this is the S-box, the single most
            // important attribute in the whole file.
            if (v instanceof de.neemann.digital.core.memory.DataField) {
                de.neemann.digital.core.memory.DataField df =
                        (de.neemann.digital.core.memory.DataField) v;
                int n = 1 << attr.get(
                        de.neemann.digital.core.element.Keys.ADDR_BITS);
                StringBuilder t = new StringBuilder();
                for (int a = 0; a < n; a++) {
                    if (a > 0) {
                        t.append(",");
                    }
                    t.append(df.getDataWord(a));
                }
                v = t.toString();
            }
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append(json(key.getKey())).append(": ")
              .append(json(String.valueOf(v)));
        }
        return sb.append("}").toString();
    }

    /** The attribute keys a component type declares, so we can dump only
     *  the ones that actually apply to it. */
    private static java.util.List<Key> keysOf(ElementLibrary lib,
                                              VisualElement ve) {
        try {
            ElementTypeDescription d = lib.getElementType(ve.getElementName());
            return d.getAttributeList();
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    private static String json(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append("\"").toString();
    }
}
