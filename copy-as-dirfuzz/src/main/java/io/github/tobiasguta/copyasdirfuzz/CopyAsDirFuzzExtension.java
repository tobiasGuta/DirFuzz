package io.github.tobiasguta.copyasdirfuzz;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class CopyAsDirFuzzExtension implements BurpExtension {
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Copy as DirFuzz");
        api.userInterface().registerContextMenuItemsProvider(new Provider());
        api.logging().logToOutput("Copy as DirFuzz loaded. Right-click an HTTP request and choose 'Copy as DirFuzz'.");
    }

    private final class Provider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequest> requests = resolveRequests(event);
            if (requests.isEmpty()) {
                return Collections.emptyList();
            }

            JMenuItem item = new JMenuItem("Copy as DirFuzz");
            item.addActionListener(ignored -> copyCommands(requests));
            return List.of(item);
        }
    }

    private List<HttpRequest> resolveRequests(ContextMenuEvent event) {
        // In message editors, use the exact request currently displayed/edited.
        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequestResponse pair = event.messageEditorRequestResponse().get().requestResponse();
            if (pair != null && pair.request() != null) {
                return List.of(pair.request());
            }
        }

        List<HttpRequest> requests = new ArrayList<>();
        for (HttpRequestResponse pair : event.selectedRequestResponses()) {
            if (pair != null && pair.request() != null) {
                requests.add(pair.request());
            }
        }
        return requests;
    }

    private void copyCommands(List<HttpRequest> requests) {
        try {
            DirFuzzCommandBuilder.ShellStyle shell = DirFuzzCommandBuilder.ShellStyle.current();
            StringBuilder output = new StringBuilder();
            for (HttpRequest request : requests) {
                RequestSnapshot snapshot = BurpRequestAdapter.from(request);
                String command = DirFuzzCommandBuilder.build(snapshot, shell);
                if (!output.isEmpty()) {
                    output.append(System.lineSeparator());
                }
                output.append(command);
            }

            String text = output.toString();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
            api.logging().logToOutput("Copied " + requests.size() + " DirFuzz command" + (requests.size() == 1 ? "" : "s") + " to clipboard.");
        } catch (Exception ex) {
            api.logging().logToError("Unable to convert request to DirFuzz command", ex);
            JOptionPane.showMessageDialog(
                    null,
                    "Unable to convert this request to a DirFuzz command:\n" + ex.getMessage(),
                    "Copy as DirFuzz",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }
}
