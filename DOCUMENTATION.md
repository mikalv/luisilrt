The call stack is composed of 16-byte structures:

<table>
    <th>
        <td>Offset</td>
        <td>Position</td>
    </th>
    <tr>
        <td>0</td>
        <td>The method's RID.</td>
    </tr>
    <tr>
        <td>4</td>
        <td>A pointer to the list of the method's locals.</td>
    </tr>
    <tr>
        <td>8</td>
        <td>A pointer to the list of the method's arguments.
    </tr>
    <tr>
        <td>12</td>
        <td>A pointer to a 8-byte structure whose first 4 bytes is the method's RID (all FF if called by LUISILRT.DLL) and whose other bytes are the return position.
    </tr>
</table>
