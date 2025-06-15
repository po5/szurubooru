"use strict";

const marked = require("marked");
const DOMPurify = require("dompurify");
const uri = require("./uri.js");

// original regex before transpilation: (?:\p{P}|\p{S})
const validPrecedingCharacters = "(?:(?:[-!-#%-\\*,-\\/:;\\?@\\[\\]_\\{\\}\\xA1\\xA7\\xAB\\xB6\\xB7\\xBB\\xBF\\u037E\\u0387\\u055A-\\u055F\\u0589\\u058A\\u05BE\\u05C0\\u05C3\\u05C6\\u05F3\\u05F4\\u0609\\u060A\\u060C\\u060D\\u061B\\u061D-\\u061F\\u066A-\\u066D\\u06D4\\u0700-\\u070D\\u07F7-\\u07F9\\u0830-\\u083E\\u085E\\u0964\\u0965\\u0970\\u09FD\\u0A76\\u0AF0\\u0C77\\u0C84\\u0DF4\\u0E4F\\u0E5A\\u0E5B\\u0F04-\\u0F12\\u0F14\\u0F3A-\\u0F3D\\u0F85\\u0FD0-\\u0FD4\\u0FD9\\u0FDA\\u104A-\\u104F\\u10FB\\u1360-\\u1368\\u1400\\u166E\\u169B\\u169C\\u16EB-\\u16ED\\u1735\\u1736\\u17D4-\\u17D6\\u17D8-\\u17DA\\u1800-\\u180A\\u1944\\u1945\\u1A1E\\u1A1F\\u1AA0-\\u1AA6\\u1AA8-\\u1AAD\\u1B4E\\u1B4F\\u1B5A-\\u1B60\\u1B7D-\\u1B7F\\u1BFC-\\u1BFF\\u1C3B-\\u1C3F\\u1C7E\\u1C7F\\u1CC0-\\u1CC7\\u1CD3\\u2010-\\u2027\\u2030-\\u2043\\u2045-\\u2051\\u2053-\\u205E\\u207D\\u207E\\u208D\\u208E\\u2308-\\u230B\\u2329\\u232A\\u2768-\\u2775\\u27C5\\u27C6\\u27E6-\\u27EF\\u2983-\\u2998\\u29D8-\\u29DB\\u29FC\\u29FD\\u2CF9-\\u2CFC\\u2CFE\\u2CFF\\u2D70\\u2E00-\\u2E2E\\u2E30-\\u2E4F\\u2E52-\\u2E5D\\u3001-\\u3003\\u3008-\\u3011\\u3014-\\u301F\\u3030\\u303D\\u30A0\\u30FB\\uA4FE\\uA4FF\\uA60D-\\uA60F\\uA673\\uA67E\\uA6F2-\\uA6F7\\uA874-\\uA877\\uA8CE\\uA8CF\\uA8F8-\\uA8FA\\uA8FC\\uA92E\\uA92F\\uA95F\\uA9C1-\\uA9CD\\uA9DE\\uA9DF\\uAA5C-\\uAA5F\\uAADE\\uAADF\\uAAF0\\uAAF1\\uABEB\\uFD3E\\uFD3F\\uFE10-\\uFE19\\uFE30-\\uFE52\\uFE54-\\uFE61\\uFE63\\uFE68\\uFE6A\\uFE6B\\uFF01-\\uFF03\\uFF05-\\uFF0A\\uFF0C-\\uFF0F\\uFF1A\\uFF1B\\uFF1F\\uFF20\\uFF3B-\\uFF3D\\uFF3F\\uFF5B\\uFF5D\\uFF5F-\\uFF65]|\\uD800[\\uDD00-\\uDD02\\uDF9F\\uDFD0]|\\uD801\\uDD6F|\\uD802[\\uDC57\\uDD1F\\uDD3F\\uDE50-\\uDE58\\uDE7F\\uDEF0-\\uDEF6\\uDF39-\\uDF3F\\uDF99-\\uDF9C]|\\uD803[\\uDD6E\\uDEAD\\uDF55-\\uDF59\\uDF86-\\uDF89]|\\uD804[\\uDC47-\\uDC4D\\uDCBB\\uDCBC\\uDCBE-\\uDCC1\\uDD40-\\uDD43\\uDD74\\uDD75\\uDDC5-\\uDDC8\\uDDCD\\uDDDB\\uDDDD-\\uDDDF\\uDE38-\\uDE3D\\uDEA9\\uDFD4\\uDFD5\\uDFD7\\uDFD8]|\\uD805[\\uDC4B-\\uDC4F\\uDC5A\\uDC5B\\uDC5D\\uDCC6\\uDDC1-\\uDDD7\\uDE41-\\uDE43\\uDE60-\\uDE6C\\uDEB9\\uDF3C-\\uDF3E]|\\uD806[\\uDC3B\\uDD44-\\uDD46\\uDDE2\\uDE3F-\\uDE46\\uDE9A-\\uDE9C\\uDE9E-\\uDEA2\\uDF00-\\uDF09\\uDFE1]|\\uD807[\\uDC41-\\uDC45\\uDC70\\uDC71\\uDEF7\\uDEF8\\uDF43-\\uDF4F\\uDFFF]|\\uD809[\\uDC70-\\uDC74]|\\uD80B[\\uDFF1\\uDFF2]|\\uD81A[\\uDE6E\\uDE6F\\uDEF5\\uDF37-\\uDF3B\\uDF44]|\\uD81B[\\uDD6D-\\uDD6F\\uDE97-\\uDE9A\\uDFE2]|\\uD82F\\uDC9F|\\uD836[\\uDE87-\\uDE8B]|\\uD839\\uDDFF|\\uD83A[\\uDD5E\\uDD5F])|(?:[\\$\\+\\^`\\|~\\xA2-\\xA6\\xA8\\xA9\\xAC\\xAE-\\xB1\\xB4\\xB8\\xD7\\xF7\\u02C2-\\u02C5\\u02D2-\\u02DF\\u02E5-\\u02EB\\u02ED\\u02EF-\\u02FF\\u0375\\u0384\\u0385\\u03F6\\u0482\\u058D-\\u058F\\u0606-\\u0608\\u060B\\u060E\\u060F\\u06DE\\u06E9\\u06FD\\u06FE\\u07F6\\u07FE\\u07FF\\u0888\\u09F2\\u09F3\\u09FA\\u09FB\\u0AF1\\u0B70\\u0BF3-\\u0BFA\\u0C7F\\u0D4F\\u0D79\\u0E3F\\u0F01-\\u0F03\\u0F13\\u0F15-\\u0F17\\u0F1A-\\u0F1F\\u0F34\\u0F36\\u0F38\\u0FBE-\\u0FC5\\u0FC7-\\u0FCC\\u0FCE\\u0FCF\\u0FD5-\\u0FD8\\u109E\\u109F\\u1390-\\u1399\\u166D\\u17DB\\u1940\\u19DE-\\u19FF\\u1B61-\\u1B6A\\u1B74-\\u1B7C\\u1FBD\\u1FBF-\\u1FC1\\u1FCD-\\u1FCF\\u1FDD-\\u1FDF\\u1FED-\\u1FEF\\u1FFD\\u1FFE\\u2044\\u2052\\u207A-\\u207C\\u208A-\\u208C\\u20A0-\\u20C0\\u2100\\u2101\\u2103-\\u2106\\u2108\\u2109\\u2114\\u2116-\\u2118\\u211E-\\u2123\\u2125\\u2127\\u2129\\u212E\\u213A\\u213B\\u2140-\\u2144\\u214A-\\u214D\\u214F\\u218A\\u218B\\u2190-\\u2307\\u230C-\\u2328\\u232B-\\u2429\\u2440-\\u244A\\u249C-\\u24E9\\u2500-\\u2767\\u2794-\\u27C4\\u27C7-\\u27E5\\u27F0-\\u2982\\u2999-\\u29D7\\u29DC-\\u29FB\\u29FE-\\u2B73\\u2B76-\\u2B95\\u2B97-\\u2BFF\\u2CE5-\\u2CEA\\u2E50\\u2E51\\u2E80-\\u2E99\\u2E9B-\\u2EF3\\u2F00-\\u2FD5\\u2FF0-\\u2FFF\\u3004\\u3012\\u3013\\u3020\\u3036\\u3037\\u303E\\u303F\\u309B\\u309C\\u3190\\u3191\\u3196-\\u319F\\u31C0-\\u31E5\\u31EF\\u3200-\\u321E\\u322A-\\u3247\\u3250\\u3260-\\u327F\\u328A-\\u32B0\\u32C0-\\u33FF\\u4DC0-\\u4DFF\\uA490-\\uA4C6\\uA700-\\uA716\\uA720\\uA721\\uA789\\uA78A\\uA828-\\uA82B\\uA836-\\uA839\\uAA77-\\uAA79\\uAB5B\\uAB6A\\uAB6B\\uFB29\\uFBB2-\\uFBC2\\uFD40-\\uFD4F\\uFDCF\\uFDFC-\\uFDFF\\uFE62\\uFE64-\\uFE66\\uFE69\\uFF04\\uFF0B\\uFF1C-\\uFF1E\\uFF3E\\uFF40\\uFF5C\\uFF5E\\uFFE0-\\uFFE6\\uFFE8-\\uFFEE\\uFFFC\\uFFFD]|\\uD800[\\uDD37-\\uDD3F\\uDD79-\\uDD89\\uDD8C-\\uDD8E\\uDD90-\\uDD9C\\uDDA0\\uDDD0-\\uDDFC]|\\uD802[\\uDC77\\uDC78\\uDEC8]|\\uD803[\\uDD8E\\uDD8F]|\\uD805\\uDF3F|\\uD807[\\uDFD5-\\uDFF1]|\\uD81A[\\uDF3C-\\uDF3F\\uDF45]|\\uD82F\\uDC9C|\\uD833[\\uDC00-\\uDCEF\\uDD00-\\uDEB3\\uDF50-\\uDFC3]|\\uD834[\\uDC00-\\uDCF5\\uDD00-\\uDD26\\uDD29-\\uDD64\\uDD6A-\\uDD6C\\uDD83\\uDD84\\uDD8C-\\uDDA9\\uDDAE-\\uDDEA\\uDE00-\\uDE41\\uDE45\\uDF00-\\uDF56]|\\uD835[\\uDEC1\\uDEDB\\uDEFB\\uDF15\\uDF35\\uDF4F\\uDF6F\\uDF89\\uDFA9\\uDFC3]|\\uD836[\\uDC00-\\uDDFF\\uDE37-\\uDE3A\\uDE6D-\\uDE74\\uDE76-\\uDE83\\uDE85\\uDE86]|\\uD838[\\uDD4F\\uDEFF]|\\uD83B[\\uDCAC\\uDCB0\\uDD2E\\uDEF0\\uDEF1]|\\uD83C[\\uDC00-\\uDC2B\\uDC30-\\uDC93\\uDCA0-\\uDCAE\\uDCB1-\\uDCBF\\uDCC1-\\uDCCF\\uDCD1-\\uDCF5\\uDD0D-\\uDDAD\\uDDE6-\\uDE02\\uDE10-\\uDE3B\\uDE40-\\uDE48\\uDE50\\uDE51\\uDE60-\\uDE65\\uDF00-\\uDFFF]|\\uD83D[\\uDC00-\\uDED7\\uDEDC-\\uDEEC\\uDEF0-\\uDEFC\\uDF00-\\uDF76\\uDF7B-\\uDFD9\\uDFE0-\\uDFEB\\uDFF0]|\\uD83E[\\uDC00-\\uDC0B\\uDC10-\\uDC47\\uDC50-\\uDC59\\uDC60-\\uDC87\\uDC90-\\uDCAD\\uDCB0-\\uDCBB\\uDCC0\\uDCC1\\uDD00-\\uDE53\\uDE60-\\uDE6D\\uDE70-\\uDE7C\\uDE80-\\uDE89\\uDE8F-\\uDEC6\\uDECE-\\uDEDC\\uDEDF-\\uDEE9\\uDEF0-\\uDEF8\\uDF00-\\uDF92\\uDF94-\\uDFEF]))";
// original regex before transpilation: (?:\\&(?:amp|lt|gt|quot|apos);|[\p{L}\p{M}\p{N}_-]|\\.)
const validTagCharacters = "(?:\\\\&(?:amp|lt|gt|quot|apos);|[-0-9A-Z_a-z\\xAA\\xB2\\xB3\\xB5\\xB9\\xBA\\xBC-\\xBE\\xC0-\\xD6\\xD8-\\xF6\\xF8-\\u02C1\\u02C6-\\u02D1\\u02E0-\\u02E4\\u02EC\\u02EE\\u0300-\\u0374\\u0376\\u0377\\u037A-\\u037D\\u037F\\u0386\\u0388-\\u038A\\u038C\\u038E-\\u03A1\\u03A3-\\u03F5\\u03F7-\\u0481\\u0483-\\u052F\\u0531-\\u0556\\u0559\\u0560-\\u0588\\u0591-\\u05BD\\u05BF\\u05C1\\u05C2\\u05C4\\u05C5\\u05C7\\u05D0-\\u05EA\\u05EF-\\u05F2\\u0610-\\u061A\\u0620-\\u0669\\u066E-\\u06D3\\u06D5-\\u06DC\\u06DF-\\u06E8\\u06EA-\\u06FC\\u06FF\\u0710-\\u074A\\u074D-\\u07B1\\u07C0-\\u07F5\\u07FA\\u07FD\\u0800-\\u082D\\u0840-\\u085B\\u0860-\\u086A\\u0870-\\u0887\\u0889-\\u088E\\u0897-\\u08E1\\u08E3-\\u0963\\u0966-\\u096F\\u0971-\\u0983\\u0985-\\u098C\\u098F\\u0990\\u0993-\\u09A8\\u09AA-\\u09B0\\u09B2\\u09B6-\\u09B9\\u09BC-\\u09C4\\u09C7\\u09C8\\u09CB-\\u09CE\\u09D7\\u09DC\\u09DD\\u09DF-\\u09E3\\u09E6-\\u09F1\\u09F4-\\u09F9\\u09FC\\u09FE\\u0A01-\\u0A03\\u0A05-\\u0A0A\\u0A0F\\u0A10\\u0A13-\\u0A28\\u0A2A-\\u0A30\\u0A32\\u0A33\\u0A35\\u0A36\\u0A38\\u0A39\\u0A3C\\u0A3E-\\u0A42\\u0A47\\u0A48\\u0A4B-\\u0A4D\\u0A51\\u0A59-\\u0A5C\\u0A5E\\u0A66-\\u0A75\\u0A81-\\u0A83\\u0A85-\\u0A8D\\u0A8F-\\u0A91\\u0A93-\\u0AA8\\u0AAA-\\u0AB0\\u0AB2\\u0AB3\\u0AB5-\\u0AB9\\u0ABC-\\u0AC5\\u0AC7-\\u0AC9\\u0ACB-\\u0ACD\\u0AD0\\u0AE0-\\u0AE3\\u0AE6-\\u0AEF\\u0AF9-\\u0AFF\\u0B01-\\u0B03\\u0B05-\\u0B0C\\u0B0F\\u0B10\\u0B13-\\u0B28\\u0B2A-\\u0B30\\u0B32\\u0B33\\u0B35-\\u0B39\\u0B3C-\\u0B44\\u0B47\\u0B48\\u0B4B-\\u0B4D\\u0B55-\\u0B57\\u0B5C\\u0B5D\\u0B5F-\\u0B63\\u0B66-\\u0B6F\\u0B71-\\u0B77\\u0B82\\u0B83\\u0B85-\\u0B8A\\u0B8E-\\u0B90\\u0B92-\\u0B95\\u0B99\\u0B9A\\u0B9C\\u0B9E\\u0B9F\\u0BA3\\u0BA4\\u0BA8-\\u0BAA\\u0BAE-\\u0BB9\\u0BBE-\\u0BC2\\u0BC6-\\u0BC8\\u0BCA-\\u0BCD\\u0BD0\\u0BD7\\u0BE6-\\u0BF2\\u0C00-\\u0C0C\\u0C0E-\\u0C10\\u0C12-\\u0C28\\u0C2A-\\u0C39\\u0C3C-\\u0C44\\u0C46-\\u0C48\\u0C4A-\\u0C4D\\u0C55\\u0C56\\u0C58-\\u0C5A\\u0C5D\\u0C60-\\u0C63\\u0C66-\\u0C6F\\u0C78-\\u0C7E\\u0C80-\\u0C83\\u0C85-\\u0C8C\\u0C8E-\\u0C90\\u0C92-\\u0CA8\\u0CAA-\\u0CB3\\u0CB5-\\u0CB9\\u0CBC-\\u0CC4\\u0CC6-\\u0CC8\\u0CCA-\\u0CCD\\u0CD5\\u0CD6\\u0CDD\\u0CDE\\u0CE0-\\u0CE3\\u0CE6-\\u0CEF\\u0CF1-\\u0CF3\\u0D00-\\u0D0C\\u0D0E-\\u0D10\\u0D12-\\u0D44\\u0D46-\\u0D48\\u0D4A-\\u0D4E\\u0D54-\\u0D63\\u0D66-\\u0D78\\u0D7A-\\u0D7F\\u0D81-\\u0D83\\u0D85-\\u0D96\\u0D9A-\\u0DB1\\u0DB3-\\u0DBB\\u0DBD\\u0DC0-\\u0DC6\\u0DCA\\u0DCF-\\u0DD4\\u0DD6\\u0DD8-\\u0DDF\\u0DE6-\\u0DEF\\u0DF2\\u0DF3\\u0E01-\\u0E3A\\u0E40-\\u0E4E\\u0E50-\\u0E59\\u0E81\\u0E82\\u0E84\\u0E86-\\u0E8A\\u0E8C-\\u0EA3\\u0EA5\\u0EA7-\\u0EBD\\u0EC0-\\u0EC4\\u0EC6\\u0EC8-\\u0ECE\\u0ED0-\\u0ED9\\u0EDC-\\u0EDF\\u0F00\\u0F18\\u0F19\\u0F20-\\u0F33\\u0F35\\u0F37\\u0F39\\u0F3E-\\u0F47\\u0F49-\\u0F6C\\u0F71-\\u0F84\\u0F86-\\u0F97\\u0F99-\\u0FBC\\u0FC6\\u1000-\\u1049\\u1050-\\u109D\\u10A0-\\u10C5\\u10C7\\u10CD\\u10D0-\\u10FA\\u10FC-\\u1248\\u124A-\\u124D\\u1250-\\u1256\\u1258\\u125A-\\u125D\\u1260-\\u1288\\u128A-\\u128D\\u1290-\\u12B0\\u12B2-\\u12B5\\u12B8-\\u12BE\\u12C0\\u12C2-\\u12C5\\u12C8-\\u12D6\\u12D8-\\u1310\\u1312-\\u1315\\u1318-\\u135A\\u135D-\\u135F\\u1369-\\u137C\\u1380-\\u138F\\u13A0-\\u13F5\\u13F8-\\u13FD\\u1401-\\u166C\\u166F-\\u167F\\u1681-\\u169A\\u16A0-\\u16EA\\u16EE-\\u16F8\\u1700-\\u1715\\u171F-\\u1734\\u1740-\\u1753\\u1760-\\u176C\\u176E-\\u1770\\u1772\\u1773\\u1780-\\u17D3\\u17D7\\u17DC\\u17DD\\u17E0-\\u17E9\\u17F0-\\u17F9\\u180B-\\u180D\\u180F-\\u1819\\u1820-\\u1878\\u1880-\\u18AA\\u18B0-\\u18F5\\u1900-\\u191E\\u1920-\\u192B\\u1930-\\u193B\\u1946-\\u196D\\u1970-\\u1974\\u1980-\\u19AB\\u19B0-\\u19C9\\u19D0-\\u19DA\\u1A00-\\u1A1B\\u1A20-\\u1A5E\\u1A60-\\u1A7C\\u1A7F-\\u1A89\\u1A90-\\u1A99\\u1AA7\\u1AB0-\\u1ACE\\u1B00-\\u1B4C\\u1B50-\\u1B59\\u1B6B-\\u1B73\\u1B80-\\u1BF3\\u1C00-\\u1C37\\u1C40-\\u1C49\\u1C4D-\\u1C7D\\u1C80-\\u1C8A\\u1C90-\\u1CBA\\u1CBD-\\u1CBF\\u1CD0-\\u1CD2\\u1CD4-\\u1CFA\\u1D00-\\u1F15\\u1F18-\\u1F1D\\u1F20-\\u1F45\\u1F48-\\u1F4D\\u1F50-\\u1F57\\u1F59\\u1F5B\\u1F5D\\u1F5F-\\u1F7D\\u1F80-\\u1FB4\\u1FB6-\\u1FBC\\u1FBE\\u1FC2-\\u1FC4\\u1FC6-\\u1FCC\\u1FD0-\\u1FD3\\u1FD6-\\u1FDB\\u1FE0-\\u1FEC\\u1FF2-\\u1FF4\\u1FF6-\\u1FFC\\u2070\\u2071\\u2074-\\u2079\\u207F-\\u2089\\u2090-\\u209C\\u20D0-\\u20F0\\u2102\\u2107\\u210A-\\u2113\\u2115\\u2119-\\u211D\\u2124\\u2126\\u2128\\u212A-\\u212D\\u212F-\\u2139\\u213C-\\u213F\\u2145-\\u2149\\u214E\\u2150-\\u2189\\u2460-\\u249B\\u24EA-\\u24FF\\u2776-\\u2793\\u2C00-\\u2CE4\\u2CEB-\\u2CF3\\u2CFD\\u2D00-\\u2D25\\u2D27\\u2D2D\\u2D30-\\u2D67\\u2D6F\\u2D7F-\\u2D96\\u2DA0-\\u2DA6\\u2DA8-\\u2DAE\\u2DB0-\\u2DB6\\u2DB8-\\u2DBE\\u2DC0-\\u2DC6\\u2DC8-\\u2DCE\\u2DD0-\\u2DD6\\u2DD8-\\u2DDE\\u2DE0-\\u2DFF\\u2E2F\\u3005-\\u3007\\u3021-\\u302F\\u3031-\\u3035\\u3038-\\u303C\\u3041-\\u3096\\u3099\\u309A\\u309D-\\u309F\\u30A1-\\u30FA\\u30FC-\\u30FF\\u3105-\\u312F\\u3131-\\u318E\\u3192-\\u3195\\u31A0-\\u31BF\\u31F0-\\u31FF\\u3220-\\u3229\\u3248-\\u324F\\u3251-\\u325F\\u3280-\\u3289\\u32B1-\\u32BF\\u3400-\\u4DBF\\u4E00-\\uA48C\\uA4D0-\\uA4FD\\uA500-\\uA60C\\uA610-\\uA62B\\uA640-\\uA672\\uA674-\\uA67D\\uA67F-\\uA6F1\\uA717-\\uA71F\\uA722-\\uA788\\uA78B-\\uA7CD\\uA7D0\\uA7D1\\uA7D3\\uA7D5-\\uA7DC\\uA7F2-\\uA827\\uA82C\\uA830-\\uA835\\uA840-\\uA873\\uA880-\\uA8C5\\uA8D0-\\uA8D9\\uA8E0-\\uA8F7\\uA8FB\\uA8FD-\\uA92D\\uA930-\\uA953\\uA960-\\uA97C\\uA980-\\uA9C0\\uA9CF-\\uA9D9\\uA9E0-\\uA9FE\\uAA00-\\uAA36\\uAA40-\\uAA4D\\uAA50-\\uAA59\\uAA60-\\uAA76\\uAA7A-\\uAAC2\\uAADB-\\uAADD\\uAAE0-\\uAAEF\\uAAF2-\\uAAF6\\uAB01-\\uAB06\\uAB09-\\uAB0E\\uAB11-\\uAB16\\uAB20-\\uAB26\\uAB28-\\uAB2E\\uAB30-\\uAB5A\\uAB5C-\\uAB69\\uAB70-\\uABEA\\uABEC\\uABED\\uABF0-\\uABF9\\uAC00-\\uD7A3\\uD7B0-\\uD7C6\\uD7CB-\\uD7FB\\uF900-\\uFA6D\\uFA70-\\uFAD9\\uFB00-\\uFB06\\uFB13-\\uFB17\\uFB1D-\\uFB28\\uFB2A-\\uFB36\\uFB38-\\uFB3C\\uFB3E\\uFB40\\uFB41\\uFB43\\uFB44\\uFB46-\\uFBB1\\uFBD3-\\uFD3D\\uFD50-\\uFD8F\\uFD92-\\uFDC7\\uFDF0-\\uFDFB\\uFE00-\\uFE0F\\uFE20-\\uFE2F\\uFE70-\\uFE74\\uFE76-\\uFEFC\\uFF10-\\uFF19\\uFF21-\\uFF3A\\uFF41-\\uFF5A\\uFF66-\\uFFBE\\uFFC2-\\uFFC7\\uFFCA-\\uFFCF\\uFFD2-\\uFFD7\\uFFDA-\\uFFDC]|\\uD800[\\uDC00-\\uDC0B\\uDC0D-\\uDC26\\uDC28-\\uDC3A\\uDC3C\\uDC3D\\uDC3F-\\uDC4D\\uDC50-\\uDC5D\\uDC80-\\uDCFA\\uDD07-\\uDD33\\uDD40-\\uDD78\\uDD8A\\uDD8B\\uDDFD\\uDE80-\\uDE9C\\uDEA0-\\uDED0\\uDEE0-\\uDEFB\\uDF00-\\uDF23\\uDF2D-\\uDF4A\\uDF50-\\uDF7A\\uDF80-\\uDF9D\\uDFA0-\\uDFC3\\uDFC8-\\uDFCF\\uDFD1-\\uDFD5]|\\uD801[\\uDC00-\\uDC9D\\uDCA0-\\uDCA9\\uDCB0-\\uDCD3\\uDCD8-\\uDCFB\\uDD00-\\uDD27\\uDD30-\\uDD63\\uDD70-\\uDD7A\\uDD7C-\\uDD8A\\uDD8C-\\uDD92\\uDD94\\uDD95\\uDD97-\\uDDA1\\uDDA3-\\uDDB1\\uDDB3-\\uDDB9\\uDDBB\\uDDBC\\uDDC0-\\uDDF3\\uDE00-\\uDF36\\uDF40-\\uDF55\\uDF60-\\uDF67\\uDF80-\\uDF85\\uDF87-\\uDFB0\\uDFB2-\\uDFBA]|\\uD802[\\uDC00-\\uDC05\\uDC08\\uDC0A-\\uDC35\\uDC37\\uDC38\\uDC3C\\uDC3F-\\uDC55\\uDC58-\\uDC76\\uDC79-\\uDC9E\\uDCA7-\\uDCAF\\uDCE0-\\uDCF2\\uDCF4\\uDCF5\\uDCFB-\\uDD1B\\uDD20-\\uDD39\\uDD80-\\uDDB7\\uDDBC-\\uDDCF\\uDDD2-\\uDE03\\uDE05\\uDE06\\uDE0C-\\uDE13\\uDE15-\\uDE17\\uDE19-\\uDE35\\uDE38-\\uDE3A\\uDE3F-\\uDE48\\uDE60-\\uDE7E\\uDE80-\\uDE9F\\uDEC0-\\uDEC7\\uDEC9-\\uDEE6\\uDEEB-\\uDEEF\\uDF00-\\uDF35\\uDF40-\\uDF55\\uDF58-\\uDF72\\uDF78-\\uDF91\\uDFA9-\\uDFAF]|\\uD803[\\uDC00-\\uDC48\\uDC80-\\uDCB2\\uDCC0-\\uDCF2\\uDCFA-\\uDD27\\uDD30-\\uDD39\\uDD40-\\uDD65\\uDD69-\\uDD6D\\uDD6F-\\uDD85\\uDE60-\\uDE7E\\uDE80-\\uDEA9\\uDEAB\\uDEAC\\uDEB0\\uDEB1\\uDEC2-\\uDEC4\\uDEFC-\\uDF27\\uDF30-\\uDF54\\uDF70-\\uDF85\\uDFB0-\\uDFCB\\uDFE0-\\uDFF6]|\\uD804[\\uDC00-\\uDC46\\uDC52-\\uDC75\\uDC7F-\\uDCBA\\uDCC2\\uDCD0-\\uDCE8\\uDCF0-\\uDCF9\\uDD00-\\uDD34\\uDD36-\\uDD3F\\uDD44-\\uDD47\\uDD50-\\uDD73\\uDD76\\uDD80-\\uDDC4\\uDDC9-\\uDDCC\\uDDCE-\\uDDDA\\uDDDC\\uDDE1-\\uDDF4\\uDE00-\\uDE11\\uDE13-\\uDE37\\uDE3E-\\uDE41\\uDE80-\\uDE86\\uDE88\\uDE8A-\\uDE8D\\uDE8F-\\uDE9D\\uDE9F-\\uDEA8\\uDEB0-\\uDEEA\\uDEF0-\\uDEF9\\uDF00-\\uDF03\\uDF05-\\uDF0C\\uDF0F\\uDF10\\uDF13-\\uDF28\\uDF2A-\\uDF30\\uDF32\\uDF33\\uDF35-\\uDF39\\uDF3B-\\uDF44\\uDF47\\uDF48\\uDF4B-\\uDF4D\\uDF50\\uDF57\\uDF5D-\\uDF63\\uDF66-\\uDF6C\\uDF70-\\uDF74\\uDF80-\\uDF89\\uDF8B\\uDF8E\\uDF90-\\uDFB5\\uDFB7-\\uDFC0\\uDFC2\\uDFC5\\uDFC7-\\uDFCA\\uDFCC-\\uDFD3\\uDFE1\\uDFE2]|\\uD805[\\uDC00-\\uDC4A\\uDC50-\\uDC59\\uDC5E-\\uDC61\\uDC80-\\uDCC5\\uDCC7\\uDCD0-\\uDCD9\\uDD80-\\uDDB5\\uDDB8-\\uDDC0\\uDDD8-\\uDDDD\\uDE00-\\uDE40\\uDE44\\uDE50-\\uDE59\\uDE80-\\uDEB8\\uDEC0-\\uDEC9\\uDED0-\\uDEE3\\uDF00-\\uDF1A\\uDF1D-\\uDF2B\\uDF30-\\uDF3B\\uDF40-\\uDF46]|\\uD806[\\uDC00-\\uDC3A\\uDCA0-\\uDCF2\\uDCFF-\\uDD06\\uDD09\\uDD0C-\\uDD13\\uDD15\\uDD16\\uDD18-\\uDD35\\uDD37\\uDD38\\uDD3B-\\uDD43\\uDD50-\\uDD59\\uDDA0-\\uDDA7\\uDDAA-\\uDDD7\\uDDDA-\\uDDE1\\uDDE3\\uDDE4\\uDE00-\\uDE3E\\uDE47\\uDE50-\\uDE99\\uDE9D\\uDEB0-\\uDEF8\\uDFC0-\\uDFE0\\uDFF0-\\uDFF9]|\\uD807[\\uDC00-\\uDC08\\uDC0A-\\uDC36\\uDC38-\\uDC40\\uDC50-\\uDC6C\\uDC72-\\uDC8F\\uDC92-\\uDCA7\\uDCA9-\\uDCB6\\uDD00-\\uDD06\\uDD08\\uDD09\\uDD0B-\\uDD36\\uDD3A\\uDD3C\\uDD3D\\uDD3F-\\uDD47\\uDD50-\\uDD59\\uDD60-\\uDD65\\uDD67\\uDD68\\uDD6A-\\uDD8E\\uDD90\\uDD91\\uDD93-\\uDD98\\uDDA0-\\uDDA9\\uDEE0-\\uDEF6\\uDF00-\\uDF10\\uDF12-\\uDF3A\\uDF3E-\\uDF42\\uDF50-\\uDF5A\\uDFB0\\uDFC0-\\uDFD4]|\\uD808[\\uDC00-\\uDF99]|\\uD809[\\uDC00-\\uDC6E\\uDC80-\\uDD43]|\\uD80B[\\uDF90-\\uDFF0]|[\\uD80C\\uD80E\\uD80F\\uD81C-\\uD820\\uD822\\uD840-\\uD868\\uD86A-\\uD86C\\uD86F-\\uD872\\uD874-\\uD879\\uD880-\\uD883\\uD885-\\uD887][\\uDC00-\\uDFFF]|\\uD80D[\\uDC00-\\uDC2F\\uDC40-\\uDC55\\uDC60-\\uDFFF]|\\uD810[\\uDC00-\\uDFFA]|\\uD811[\\uDC00-\\uDE46]|\\uD818[\\uDD00-\\uDD39]|\\uD81A[\\uDC00-\\uDE38\\uDE40-\\uDE5E\\uDE60-\\uDE69\\uDE70-\\uDEBE\\uDEC0-\\uDEC9\\uDED0-\\uDEED\\uDEF0-\\uDEF4\\uDF00-\\uDF36\\uDF40-\\uDF43\\uDF50-\\uDF59\\uDF5B-\\uDF61\\uDF63-\\uDF77\\uDF7D-\\uDF8F]|\\uD81B[\\uDD40-\\uDD6C\\uDD70-\\uDD79\\uDE40-\\uDE96\\uDF00-\\uDF4A\\uDF4F-\\uDF87\\uDF8F-\\uDF9F\\uDFE0\\uDFE1\\uDFE3\\uDFE4\\uDFF0\\uDFF1]|\\uD821[\\uDC00-\\uDFF7]|\\uD823[\\uDC00-\\uDCD5\\uDCFF-\\uDD08]|\\uD82B[\\uDFF0-\\uDFF3\\uDFF5-\\uDFFB\\uDFFD\\uDFFE]|\\uD82C[\\uDC00-\\uDD22\\uDD32\\uDD50-\\uDD52\\uDD55\\uDD64-\\uDD67\\uDD70-\\uDEFB]|\\uD82F[\\uDC00-\\uDC6A\\uDC70-\\uDC7C\\uDC80-\\uDC88\\uDC90-\\uDC99\\uDC9D\\uDC9E]|\\uD833[\\uDCF0-\\uDCF9\\uDF00-\\uDF2D\\uDF30-\\uDF46]|\\uD834[\\uDD65-\\uDD69\\uDD6D-\\uDD72\\uDD7B-\\uDD82\\uDD85-\\uDD8B\\uDDAA-\\uDDAD\\uDE42-\\uDE44\\uDEC0-\\uDED3\\uDEE0-\\uDEF3\\uDF60-\\uDF78]|\\uD835[\\uDC00-\\uDC54\\uDC56-\\uDC9C\\uDC9E\\uDC9F\\uDCA2\\uDCA5\\uDCA6\\uDCA9-\\uDCAC\\uDCAE-\\uDCB9\\uDCBB\\uDCBD-\\uDCC3\\uDCC5-\\uDD05\\uDD07-\\uDD0A\\uDD0D-\\uDD14\\uDD16-\\uDD1C\\uDD1E-\\uDD39\\uDD3B-\\uDD3E\\uDD40-\\uDD44\\uDD46\\uDD4A-\\uDD50\\uDD52-\\uDEA5\\uDEA8-\\uDEC0\\uDEC2-\\uDEDA\\uDEDC-\\uDEFA\\uDEFC-\\uDF14\\uDF16-\\uDF34\\uDF36-\\uDF4E\\uDF50-\\uDF6E\\uDF70-\\uDF88\\uDF8A-\\uDFA8\\uDFAA-\\uDFC2\\uDFC4-\\uDFCB\\uDFCE-\\uDFFF]|\\uD836[\\uDE00-\\uDE36\\uDE3B-\\uDE6C\\uDE75\\uDE84\\uDE9B-\\uDE9F\\uDEA1-\\uDEAF]|\\uD837[\\uDF00-\\uDF1E\\uDF25-\\uDF2A]|\\uD838[\\uDC00-\\uDC06\\uDC08-\\uDC18\\uDC1B-\\uDC21\\uDC23\\uDC24\\uDC26-\\uDC2A\\uDC30-\\uDC6D\\uDC8F\\uDD00-\\uDD2C\\uDD30-\\uDD3D\\uDD40-\\uDD49\\uDD4E\\uDE90-\\uDEAE\\uDEC0-\\uDEF9]|\\uD839[\\uDCD0-\\uDCF9\\uDDD0-\\uDDFA\\uDFE0-\\uDFE6\\uDFE8-\\uDFEB\\uDFED\\uDFEE\\uDFF0-\\uDFFE]|\\uD83A[\\uDC00-\\uDCC4\\uDCC7-\\uDCD6\\uDD00-\\uDD4B\\uDD50-\\uDD59]|\\uD83B[\\uDC71-\\uDCAB\\uDCAD-\\uDCAF\\uDCB1-\\uDCB4\\uDD01-\\uDD2D\\uDD2F-\\uDD3D\\uDE00-\\uDE03\\uDE05-\\uDE1F\\uDE21\\uDE22\\uDE24\\uDE27\\uDE29-\\uDE32\\uDE34-\\uDE37\\uDE39\\uDE3B\\uDE42\\uDE47\\uDE49\\uDE4B\\uDE4D-\\uDE4F\\uDE51\\uDE52\\uDE54\\uDE57\\uDE59\\uDE5B\\uDE5D\\uDE5F\\uDE61\\uDE62\\uDE64\\uDE67-\\uDE6A\\uDE6C-\\uDE72\\uDE74-\\uDE77\\uDE79-\\uDE7C\\uDE7E\\uDE80-\\uDE89\\uDE8B-\\uDE9B\\uDEA1-\\uDEA3\\uDEA5-\\uDEA9\\uDEAB-\\uDEBB]|\\uD83C[\\uDD00-\\uDD0C]|\\uD83E[\\uDFF0-\\uDFF9]|\\uD869[\\uDC00-\\uDEDF\\uDF00-\\uDFFF]|\\uD86D[\\uDC00-\\uDF39\\uDF40-\\uDFFF]|\\uD86E[\\uDC00-\\uDC1D\\uDC20-\\uDFFF]|\\uD873[\\uDC00-\\uDEA1\\uDEB0-\\uDFFF]|\\uD87A[\\uDC00-\\uDFE0\\uDFF0-\\uDFFF]|\\uD87B[\\uDC00-\\uDE5D]|\\uD87E[\\uDC00-\\uDE1D]|\\uD884[\\uDC00-\\uDF4A\\uDF50-\\uDFFF]|\\uD888[\\uDC00-\\uDFAF]|\\uDB40[\\uDD00-\\uDDEF]|\\\\(?:[\\0-\\t\\x0B\\f\\x0E-\\u2027\\u202A-\\uD7FF\\uE000-\\uFFFF]|[\\uD800-\\uDBFF][\\uDC00-\\uDFFF]|[\\uD800-\\uDBFF](?![\\uDC00-\\uDFFF])|(?:[^\\uD800-\\uDBFF]|^)[\\uDC00-\\uDFFF]))";
// equivalent to \s when in unicode mode
const unicodeSpace = "[\\t-\\r \\xA0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";

class BaseMarkdownWrapper {
    init(text) {
        return text;
    }

    preprocess(text) {
        return text;
    }

    postprocess(text) {
        return text;
    }
}

class SjisWrapper extends BaseMarkdownWrapper {
    constructor() {
        super();
        this.buf = [];
    }

    preprocess(text) {
        return text.replace(
            /\[sjis\]((?:[^\[]|\[(?!\/?sjis\]))+)\[\/sjis\]/gi,
            (match, capture) => {
                var ret = "%%%SJIS" + this.buf.length;
                this.buf.push(capture);
                return ret;
            }
        );
    }

    postprocess(text) {
        return text.replace(
            /(?:<p>)?%%%SJIS(\d+)(?:<\/p>)?/,
            (match, capture) => {
                return '<div class="sjis">' + this.buf[capture] + "</div>";
            }
        );
    }
}

class SearchPermalinkWrapper extends BaseMarkdownWrapper {
    init(text) {
        return text.replace(
            /\[search\]((?:[^\[]|\[(?!\/?search\]))+)\[\/search\]/gi,
            (match, capture) => `<#${escapeMarkdown(capture.replace(/\\(.)/g, "$1"))}>`
        );
    }
}

class EntityPermalinkWrapper extends BaseMarkdownWrapper {
    init(text) {
        // enclosed entity shortlinks e.g. <#my tags>
        return text.replace(
            new RegExp(`(^|[^\\(\\\\])<([#+?])(.*?[^\\\\])>`, "mg"),
            (match, lookbehind, prefix, capture) => `${lookbehind}${prefix}${escapeMarkdown(capture.replace(/\\(.)/g, "$1")).replace(/ /g, "\\ ")}`
        );
    }
}

class SpoilersWrapper extends BaseMarkdownWrapper {
    postprocess(text) {
        return text.replace(
            /\[spoiler\]((?:[^\[]|\[(?!\/?spoiler\]))+)\[\/spoiler\]/gi,
            '<span class="spoiler">$1</span>'
        );
    }
}

class SmallWrapper extends BaseMarkdownWrapper {
    postprocess(text) {
        return text.replace(
            /\[small\]((?:[^\[]|\[(?!\/?small\]))+)\[\/small\]/gi,
            "<small>$1</small>"
        );
    }
}

class FaviconWrapper extends BaseMarkdownWrapper {
    preprocess(text) {
        return text.replace(
            /\[icon\]((?:[^\[]|\[(?!\/?icon\]))+)\[\/icon\]/gi,
            '<a href="$1"><img src="https://www.google.com/s2/favicons?domain=$1"> $1</a>'
        );
    }
}

function escapeHtml(unsafe) {
    return unsafe
        .toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
}

function unescapeHtml(unsafe) {
    return unsafe
        .toString()
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, "\"")
        .replace(/&apos;/g, "'")
        .replace(/&amp;/g, "&");
}

function escapeMarkdown(unsafe) {
    return unsafe
        .toString()
        .replace(/([\/\\!"#$%&'()<>*+,.:;=?@[\]^_`{|}~-])/g, "\\$1");
}

function createRenderer() {
    const renderer = new marked.Renderer();
    renderer.image = (href, title, alt) => {
        let [_, url, width, height] =
            /^(.+?)(?:\s=\s*(\d*)\s*x\s*(\d*)\s*)?$/.exec(href);
        let res = '<img src="' + escapeHtml(url) + '" alt="' + escapeHtml(alt);
        if (width) {
            res += '" width="' + width;
        }
        if (height) {
            res += '" height="' + height;
        }
        return res + '">';
    };
    return renderer;
}

function resolveEntity(prefix, capture, text, getPrettyName) {
    let href;
    capture = unescapeHtml(capture);
    text = unescapeHtml(text);

    if (prefix === "@") {
        href = uri.formatClientLink("post", capture);
        return { href: href, text: text };
    }

    capture = capture.replace(/\\(.)/g, "$1");
    text = text.replace(/\\(.)/g, "$1");

    if (prefix === "#") {
        href = uri.formatClientLink("posts", { query: uri.escapeTagName(capture) });
    } else if (prefix === "+") {
        href = uri.formatClientLink("user", capture);
    } else if (prefix === "?") {
        href = uri.formatClientLink("tag", capture);
    }

    if (prefix !== "+") {
        text = getPrettyName(text);
    }

    return { href: href, text: text };
}

function modifyLink(token, getPrettyName) {
    let match;
    // post number links, tag shortlinks etc.
    if ((match = /^(@)(\d+)\b/.exec(token.href))) {
        const entity = resolveEntity(match[1], match[2], token.text, getPrettyName);
        token.href = entity.href;
        token.text = entity.text;
    } else if ((match = /^([#+?])(.+)$/.exec(token.href))) {
        const entity = resolveEntity(match[1], match[2], token.text, getPrettyName);
        token.href = entity.href;
        token.text = entity.text;

        if (token.tokens) {
            for (const innerToken of token.tokens) {
                if (innerToken.type !== "escape") {
                    innerToken.type = "text";
                    innerToken.text = innerToken.raw.replace(/\\(.)/g, "$1");
                }
            }
        }
    }
}

function flattenTokens(tokens) {
    const allowedTypes = ["text", "escape", "strong", "em", "del", "emStrong"];
    let i = 0;
    while (i < tokens.length) {
        const currentToken = tokens[i];

        if (currentToken.tokens) {
            flattenTokens(currentToken.tokens);
        }

        const nextToken = tokens[i + 1];
        if (!nextToken) break;

        if (nextToken.tokens) {
            flattenTokens(nextToken.tokens);
        }

        const isCurrentCombinable = allowedTypes.includes(currentToken.type);
        const isNextCombinable = allowedTypes.includes(nextToken.type);

        if (isCurrentCombinable && isNextCombinable) {
            currentToken.raw += nextToken.raw;
            currentToken.text += nextToken.text;
            currentToken.type = "text";

            if (nextToken.tokens && nextToken.tokens.length > 0) {
                if (!currentToken.tokens) {
                    currentToken.tokens = [];
                }
                currentToken.tokens.push(...nextToken.tokens);
            }

            if (currentToken.tokens) {
                flattenTokens(currentToken.tokens);
            }

            tokens.splice(i + 1, 1);
        } else {
            i++;
        }
    }
}

function modifyTokens(tokens, getPrettyName) {
    let inLink = false;

    function buildEntityLink(match, lookbehind, prefix, capture) {
        const entity = resolveEntity(prefix, capture, `${prefix}${capture}`, getPrettyName);
        return `${lookbehind}<a href="${escapeHtml(entity.href)}">${escapeHtml(entity.text)}</a>`;
    }

    function walk(innerTokens) {
        for (const token of innerTokens) {
            if (token.inLink !== undefined) inLink = token.inLink;
            if ((token.type === "text" || token.type === "blockquote") && !inLink) {
                token.text = token.raw;
                // post number links e.g. @123
                token.text = token.text.replace(
                    new RegExp(`(^|${unicodeSpace}|${validPrecedingCharacters})(@)(\\d+\\b)`, "mg"),
                    buildEntityLink
                );
                // entity shortlinks e.g. #my\ tags
                token.text = token.text.replace(
                    new RegExp(`(^|${unicodeSpace}|${validPrecedingCharacters})([#+?])(${validTagCharacters}+)`, "mg"),
                    buildEntityLink
                );
                token.text = smartypants(token.text);
            }
            if (token.tokens) {
                walk(token.tokens);
            }
        }
    }

    flattenTokens(tokens);
    walk(tokens);
}

function smartypants(text) {
    const div = document.createElement("div");
    div.innerHTML = text;
    function walk(node) {
        for (const child of node.childNodes) {
            if (child.nodeType === Node.TEXT_NODE) {
                const parsed = document.createElement("span");
                parsed.innerHTML = parseTypeSubset(escapeHtml(child.textContent), ["strong", "em", "del", "emStrong"])
                    // em-dashes
                    .replace(/---/g, "\u2014")
                    // en-dashes
                    .replace(/--/g, "\u2013")
                    // opening singles
                    .replace(/(^|[-\u2014/(\[{"\s])'/g, "$1\u2018")
                    // closing singles & apostrophes
                    .replace(/'/g, "\u2019")
                    // opening doubles
                    .replace(/(^|[-\u2014/(\[{\u2018\s])"/g, "$1\u201c")
                    // closing doubles
                    .replace(/"/g, "\u201d")
                    // ellipses
                    .replace(/\.{3}/g, "\u2026")
                    // escapes
                    .replace(new RegExp(`\\\\(${validPrecedingCharacters})`, "g"), "$1");
                node.replaceChild(parsed, child);
            } else if (child.nodeType === Node.ELEMENT_NODE && child.tagName !== "A") {
                walk(child);
            }
        }
    }
    walk(div);
    return div.innerHTML;
}

// this is necessary to not mangle inline links later when processing entity permalinks
function parseLinksOnly(text, getPrettyName) {
    let inRawBlock = false;
    const renderer = createRenderer();
    const options = {
        renderer: renderer,
        breaks: true,
        walkTokens: (token) => {
            if (token.inRawBlock !== undefined) inRawBlock = token.inRawBlock;
            if (token.type === "link" && !inRawBlock) {
                modifyLink(token, getPrettyName);
            } else if (token.type === "blockquote") {
                token.type = "html";
                token.text = `\n>${escapeHtml(token.text).replace(/\n\n+/g, "<br><br>").replace(/\n(?!$)/g, "<br>")}`;
            } else if (token.type !== "br") {
                token.type = "text";
                token.text = escapeHtml(token.raw);
            }
        },
    };

    return marked.parse(text, options).replace(/^<p>|<\/p>\s*$/g, "")
}

function parseTypeSubset(text, allowedTypes) {
    const renderer = createRenderer();
    const options = {
        renderer: renderer,
        breaks: true,
        walkTokens: (token) => {
            if (!allowedTypes.includes(token.type)) {
                token.type = "text";
                token.text = token.raw;
            }
        },
    };

    return marked.parseInline(text, options)
}

function formatMarkdown(text, getPrettyName) {
    const renderer = createRenderer();
    const options = {
        renderer: renderer,
        breaks: true,
    };
    let wrappers = [
        new SjisWrapper(),
        new SearchPermalinkWrapper(),
        new EntityPermalinkWrapper(),
        new SpoilersWrapper(),
        new SmallWrapper(),
        new FaviconWrapper(),
    ];
    for (let wrapper of wrappers) {
        text = wrapper.init(text);
    }
    text = parseLinksOnly(text, getPrettyName);
    for (let wrapper of wrappers) {
        text = wrapper.preprocess(text);
    }
    const tokens = marked.Lexer.lex(text);
    modifyTokens(tokens, getPrettyName);
    text = marked.Parser.parse(tokens, options);
    wrappers.reverse();
    for (let wrapper of wrappers) {
        text = wrapper.postprocess(text);
    }
    return DOMPurify.sanitize(text);
}

function formatInlineMarkdown(text, getPrettyName) {
    const renderer = createRenderer();
    const options = {
        renderer: renderer,
        breaks: true,
    };
    let wrappers = [
        new SearchPermalinkWrapper(),
        new EntityPermalinkWrapper(),
        new SpoilersWrapper(),
        new SmallWrapper(),
        new FaviconWrapper(),
    ];
    for (let wrapper of wrappers) {
        text = wrapper.init(text);
    }
    text = parseLinksOnly(text, getPrettyName);
    for (let wrapper of wrappers) {
        text = wrapper.preprocess(text);
    }
    const tokens = marked.Lexer.lexInline(text);
    modifyTokens(tokens, getPrettyName);
    text = marked.Parser.parseInline(tokens, options);
    wrappers.reverse();
    for (let wrapper of wrappers) {
        text = wrapper.postprocess(text);
    }
    return DOMPurify.sanitize(text);
}

module.exports = {
    formatMarkdown: formatMarkdown,
    formatInlineMarkdown: formatInlineMarkdown,
    escapeHtml: escapeHtml,
};
