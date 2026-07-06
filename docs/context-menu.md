

## Context Menu Documentation

### Overview

Right-clicking in packet views, payload panes, Conv, Crypt, List, Stats, Notes, and other data panels in the <a href="/frontend">frontend</a> opens the **context menu**. The menu is fully context-aware and only shows entries that apply to what is currently selected and which tab is active.

---

### Copy

Quick-access copy commands for current selection and payload data.

| Item                 | Description                                                                             |
| -------------------- | --------------------------------------------------------------------------------------- |
| **Copy**             | Copy the currently highlighted text to the clipboard. Shown only when selected context is greater than 1 byte. |
| **Copy Hex**         | Copy the raw payload bytes as a hex string.                                             |
| **Copy ASCII**       | Copy the printable ASCII representation of the payload.                                 |
| **Copy Raw payload** | Copy the raw payload bytes.                                                             |
| **Copy Cookies**     | Copy all session cookie jar entries as a formatted string.                              |

---

### Paste

Paste clipboard text into the focused input element.

---

### Convert to...

Load the selected text or current packet data into the **Conv** tab with a specific input format pre-selected. The Conv tab is automatically opened and **Convert** is run.

| Item                               | Description                                                                                                         |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **as Hex**                         | Load the selection as a hex-encoded byte string.                                                                    |
| **as Binary**                      | Load the selection as a binary bit-string.                                                                          |
| **as Base64**                      | Load the selection as a base64-encoded string.                                                                      |
| **as Decimal bytes**               | Load the selection as space-separated decimal byte values.                                                          |
| **as ASCII / UTF-8**               | Load the selection as plain text.                                                                                   |
| **Derive Type**                    | Run data-type guessing on selected/context text and show ranked type guesses in Conv Data Insights.                |
| **Cursor ASCII to Conv tab**       | Load the ASCII run at the current hex-grid cursor (or selected byte) into Conv.                                    |
| **Raw Payload to Conv tab**        | Load the current packet's full raw payload as hex into Conv and run conversion.                                    |
| **Decompress to Conv tab**         | If Conv input appears compressed (gzip/deflate/brotli), decompress it and load the decompressed bytes into Conv.   |
| **Import file to Conv tab**        | Open a file picker, load file bytes into Conv as hex, and apply manual-import size limits/warnings from Settings.  |

---

### Follow stream...

Shown when the current packet can be mapped to a stream tuple.

| Item                                 | Description                                                                                                  |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| **Stream to Conv tab**               | Reassembles the bidirectional stream payload and loads it into Conv as hex.                                |
| **Stream to Conv tab (decompressed)**| Reassembles stream payload, attempts decompression, then loads result into Conv as hex.                    |
| **Stream to Crypt tab**              | Reassembles stream payload and loads ASCII view of stream data into the Crypt certificate input workspace. |

Large streams may prompt for confirmation before loading.

---

### Filter...

Build and append filter expressions to the filter bar based on attributes of the current packet. Multiple sub-menus control how the new clause is combined with any existing expression.

| Sub-menu             | Description                                                                                  |
| -------------------- | --------------------------------------------------------------------------------------------- |
| **Add with &&**      | Append the new clause joined with `&&` (AND) to the existing filter.                         |
| **Add with \|\|**    | Append the new clause joined with `\|\|` (OR) to the existing filter.                        |
| **is not**           | Append a negated (`!`) clause joined with `&&` to the existing filter.                       |
| **Parentheses**      | Insert parentheses into the filter expression.                                              |
| **Clear and...**     | Clear the existing filter, then set the new clause as the complete filter.                   |

Each directional sub-menu (**Add with &&**, **Add with ||**, **is not**, **Clear and...**) can expose the same protocol/attribute options when data exists:

| Option                      | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| **Add IP to Filter**        | Adds the source or destination IP of the current packet. |
| **Add Port to Filter**      | Adds the destination port of the current packet.         |
| **Add MAC to Filter**       | Adds the source MAC address of the current packet.       |
| **Add Link Proto**          | Adds `link.proto` for the packet (L2 protocol).          |
| **Add Transport Proto**     | Adds `transport.proto` for the packet.                   |
| **Add Application Proto**   | Adds `application.proto` when available.                 |
| **Add Both Protos**         | Adds combined link/transport/application protocol clause.|
| **Add MIME Type to Filter** | Adds the detected MIME type.                             |

The **Parentheses** sub-menu provides:

| Option                            | Description                                             |
| --------------------------------- | ------------------------------------------------------- |
| **Append (**                      | Append an opening parenthesis to the filter expression. |
| **Append )**                      | Append a closing parenthesis to the filter expression.  |
| **Wrap with (...)**               | Surround the entire existing filter with parentheses.   |

When right-clicking directly in the filter input, PacketSnitch also exposes **Save current filter...** so the current query can be stored in the user filter library with a custom label.

---

### Add to Keystore...

Save highlighted text or current context data directly to the keychain. Three levels of sub-menus select the entry type and the target keychain.

| Type                  | Session keychain | Persistent keychain |
| --------------------- | ---------------- | ------------------- |
| **As Password**       | ✓                | ✓                   |
| **As Private Key**    | ✓                | ✓                   |
| **As Certificate**    | ✓                | ✓                   |
| **As Session Cookie** | ✓                | ✓                   |
| **Manual URI**        | ✓                | ✓                   |

Selecting a persistent target will prompt for the keychain password if it has not been unlocked yet.

The **Manual URI** options open a dialog to manually enter any `http://` or `https://` URL. The entered URL is saved as a `url` type entry in the selected keychain. Entries of this type can be opened directly in the system browser via the **Open link** button in the Keystore tab.

---

### Send to Notes...

Send the current selection or Conv output directly to a new note in the Notes workspace.

| Item                            | Description                                                                      |
| ------------------------------- | -------------------------------------------------------------------------------- |
| **Selected/context data**       | Creates a new note containing the currently selected text or packet context.     |
| **List row visible data**       | Creates a note from the currently selected List row's visible columns.           |
| **Conv converted output**       | Creates a new note containing the current Conv tab conversion output.            |
| **Conv hashes**                 | Creates a new note containing the current Conv tab hash outputs.                 |

This submenu is only visible when there is context data available (selected text or active Conv output).

---

### Export...

Save and export packet and session data.

| Item                       | Description                                                    |
| -------------------------- | -------------------------------------------------------------- |
| **Packet**                | Save the selected packet's serialized packet data to a file.    |
| **Payload**               | Save only the payload bytes of the current packet to a file.    |
| **Conv input**            | Export current Conv input text.                                 |
| **Conv Raw**              | Save Conv byte data as raw binary output.                       |
| **Conv output (hex)**     | Export Conv converted hex output.                               |
| **Conv output (binary)**  | Export Conv converted binary output.                            |
| **Conv output (decimal)** | Export Conv converted decimal-byte output.                      |
| **Conv output (integer)** | Export Conv big-endian integer output.                          |
| **Conv output (ASCII)**   | Export Conv ASCII output.                                       |
| **Conv output (base64)**  | Export Conv base64 output.                                      |
| **Conv hashes**           | Export all hash outputs shown in Conv Hashes.                   |
| **Conv decode output**    | Export current decoded protocol output from Conv Decodes.       |
| **Cookie Jar**            | Save all extracted cookies to disk.                             |

---

### HTTP Body...

Shown only when the current packet contains an HTTP response body.

| Item                    | Description                                                           |
| ----------------------- | --------------------------------------------------------------------- |
| **Body to Conv tab** | Load HTTP body bytes as hex into Conv and run conversion. |
| **Body to Conv tab (decompressed)** | Decompress HTTP body first, then load into Conv.    |
| **Browser preview**  | Open HTTP body in the system browser for preview.   |
| **Browser preview (decompressed)** | Decompress first, then preview in browser.       |

HTTP body actions use stream reassembly and honor `Content-Length` / chunked framing when available.

---

### File Carving...

Shown when at least one carve target is available for the current packet or stream.

| Item                    | Description                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| **HTTP body to file**   | Save the extracted HTTP response body to a file, using the Content-Type to infer the extension. |
| **HTTP body to file (decompressed)** | Decompress the HTTP body first, then save the resulting bytes to a file.                     |
| **SMB file to disk**    | Detect files transferred in the current SMB stream, let you pick one, then save it as binary.  |
| **NFS file to disk**    | Detect files transferred in the current NFS stream, let you pick one, then save it as binary.  |
| **FTP file to disk**    | Detect file transfer bytes in FTP streams, then save the carved result as binary.              |

---

### LLM Actions

Shown only when LLM is enabled in Settings and packet context is available.

| Item                          | Description                                                                                                         |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Ask PS a question...**      | Opens a prompt dialog, then asks the LLM a user-supplied question with packet context and optional selected text. |
| **Explain this data...**      | Sends selected/context data plus packet context to the LLM and requests a concise analyst-focused explanation.     |

Both actions write results into a new note and switch to the Notes workspace.

---

### Save Session

Located at the very bottom of the context menu, **Save Session** saves the loaded capture plus UI session state (packet cursor, filters/history, tabs, bookmarks, and session keychain) as a JSON file.
