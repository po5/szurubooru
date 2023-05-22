<ul>
    <li><%- ctx.postCount %> posts</li><span class='sep'>
    </span><li>Running <a href='https://github.com/po5/szurubooru/tree/vb'>szurubooru</a></li><span class='sep'>
    </span><% if (ctx.canListSnapshots) { %><li><a href='<%- ctx.formatClientLink('history') %>'>History</a></li><span class='sep'>
    </span><% } %>
</ul>
