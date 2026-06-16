<p align="center">
<a href="https://oxasploits.github.io/PacketSnitch/" alt="PacketSnitch by oxasploits"><img src="https://raw.githubusercontent.com/oxasploits/PacketSnitch/refs/heads/main/logo/ps-tagline-flicker.gif"></a>
</p>

## Context Menu Documentation

### Overview

Right-clicking in the packet views, payload panes, Conv tab, or other data panels opens the **context menu**. The menu dynamically adapts its available items based on the current context (whether text is selected, whether the current packet contains an HTTP body, etc.). Context menu items have been shortened for better fit and visual appeal.

---

### Copy

Quick-access copy commands for current selection and payload data.

| Item                 | Description                                                                             |
| -------------------- | --------------------------------------------------------------------------------------- |
| **Copy**             | Copy the currently highlighted text to the clipboard. Shown only when text is selected. |
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
| **Hex**                            | Load the selection as a hex-encoded byte string.                                                                    |
| **Binary**                         | Load the selection as a binary bit-string.                                                                          |
| **Base64**                         | Load the selection as a base64-encoded string.                                                                      |
| **Decimal bytes**                  | Load the selection as space-separated decimal byte values.                                                          |
| **ASCII / UTF-8**                  | Load the selection as a plain text string.                                                                          |
| **Data Type Guess**                | Run the data-type guesser on the selected text and show the ranked type guesses in the Conv tab's Data Insights.    |
| **Cursor ASCII to Conv**            | Load the ASCII string at the current hex-grid cursor position into the Conv tab input as ASCII / UTF-8.            |
| **Payload to Conv**                | Load the current packet's full raw payload as hex into Conv and run conversion.                                     |

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

Each directional sub-menu (**Add with &&**, **Add with ||**, **is not**, **Clear and...**) has the same five attribute options:

| Option                      | Description                                              |
| --------------------------- | -------------------------------------------------------- |
| **Add IP to Filter**        | Adds the source or destination IP of the current packet. |
| **Add Port to Filter**      | Adds the destination port of the current packet.         |
| **Add MAC to Filter**       | Adds the source MAC address of the current packet.       |
| **Add Protocol to Filter**  | Adds the detected application protocol.                  |
| **Add MIME Type to Filter** | Adds the detected MIME type.                             |

The **Parentheses** sub-menu provides:

| Option                            | Description                                             |
| --------------------------------- | ------------------------------------------------------- |
| **Append (**                      | Append an opening parenthesis to the filter expression. |
| **Append )**                      | Append a closing parenthesis to the filter expression.  |
| **Wrap with (...)**               | Surround the entire existing filter with parentheses.   |

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
| **Conv converted output**       | Creates a new note containing the current Conv tab conversion output.            |
| **Conv hashes**                 | Creates a new note containing the current Conv tab hash outputs.                 |

This submenu is only visible when there is context data available (selected text or active Conv output).

---

### Export...

Save and export packet and session data.

| Item                       | Description                                                    |
| -------------------------- | -------------------------------------------------------------- |
| **Export Packet**          | Save the raw data of the current packet to a file.             |
| **Export Payload**         | Save only the payload bytes of the current packet to a file.   |
| **Save to cookie_jar.txt** | Append all session cookies to a `cookie_jar.txt` file on disk. |

---

### HTTP File...

Shown only when the current packet contains an HTTP response body.

| Item                        | Description                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| **Save body to file**       | Save the extracted HTTP response body to a file, using the Content-Type to infer the extension. |
| **Load body into Conv**     | Load the HTTP body bytes as hex into the Conv tab and run conversion.                           |
| **Preview in browser**      | Open the HTTP body in the system's default web browser for preview.                             |

---

### Save Session

Located at the very bottom of the context menu, **Save Session** saves the loaded capture plus UI session state (packet cursor, filters/history, tabs, bookmarks, and session keychain) as a JSON file.
