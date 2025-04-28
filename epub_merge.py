import sys, os
import logging

logger = logging.getLogger(__name__)
version = "3.2.1"
from six import text_type as unicode
from six.moves.urllib.parse import unquote
from io import BytesIO

import re
from posixpath import normpath
from optparse import OptionParser
from functools import partial

from zipfile import ZipFile, ZIP_STORED, ZIP_DEFLATED
from time import time, sleep

from xml.dom.minidom import parse, parseString, getDOMImplementation, Element

from six import text_type

try:
    from six import ensure_binary
except:
    from six import binary_type


    def ensure_binary(s, encoding='utf-8', errors='strict'):
        if isinstance(s, text_type):
            return s.encode(encoding, errors)
        elif isinstance(s, binary_type):
            return s
        else:
            raise TypeError("not expecting type '%s'" % type(s))
ADOBE_OBFUSCATION = 'http://ns.adobe.com/pdf/enc#RC'
IDPF_OBFUSCATION = 'http://www.idpf.org/2008/embedding'
from itertools import cycle


class FontDecrypter:
    def __init__(self, epub, content_dom):
        self.epub = epub
        self.content_dom = content_dom
        self.encryption = {}
        self.old_uuid = None

    def get_file(self, href):
        return self.epub.read(href)

    def get_encrypted_fontfiles(self):
        if not self.encryption:
            try:
                encryption = self.epub.read("META-INF/encryption.xml")
                encryptiondom = parseString(encryption)
                for encdata in encryptiondom.getElementsByTagName('enc:EncryptedData'):
                    algorithm = encdata.getElementsByTagName('enc:EncryptionMethod')[0].getAttribute('Algorithm')
                    if algorithm not in {ADOBE_OBFUSCATION, IDPF_OBFUSCATION}:
                        logger.warning("Unknown font encryption: %s" % algorithm)
                    else:
                        for encref in encdata.getElementsByTagName('enc:CipherReference'):
                            self.encryption[encref.getAttribute('URI')] = algorithm
            except KeyError as ke:
                self.encryption = {}
        return self.encryption

    def get_old_uuid(self):
        if not self.old_uuid:
            contentdom = self.content_dom
            uidkey = contentdom.getElementsByTagName("package")[0].getAttribute("unique-identifier")
            for dcid in contentdom.getElementsByTagName("dc:identifier"):
                if dcid.getAttribute("id") == uidkey:  # and dcid.getAttribute("opf:scheme") == "uuid":
                    self.old_uuid = dcid.firstChild.data
        return self.old_uuid

    def get_idpf_key(self):
        # idpf key:urn:uuid:221c69fe-29f3-4cb4-bb3f-58c430261cc6
        # idpf key:b'\xfb\xa9\x03N}\xae~\x12 \xaa\xe0\xc11\xe2\xe7\x1b\xf6\xa5\xcas'
        idpf_key = self.get_old_uuid()
        import uuid, hashlib
        idpf_key = re.sub('[\u0020\u0009\u000d\u000a]', '', idpf_key)
        idpf_key = hashlib.sha1(idpf_key.encode('utf-8')).digest()
        return idpf_key

    def get_adobe_key(self):
        # adobe key:221c69fe-29f3-4cb4-bb3f-58c430261cc6
        # adobe key:b'"\x1ci\xfe)\xf3L\xb4\xbb?X\xc40&\x1c\xc6'
        adobe_key = self.get_old_uuid()
        import uuid
        adobe_key = adobe_key.rpartition(':')[-1]  # skip urn:uuid:
        adobe_key = uuid.UUID(adobe_key).bytes
        return adobe_key

    def get_decrypted_font_data(self, uri):
        # print(self.get_old_uuid())
        # print("idpf : %s"%self.get_idpf_key())
        # print("adobe: %s"%self.get_adobe_key())
        # print("uri:%s"%uri)
        font_data = self.get_file(uri)
        if uri in self.get_encrypted_fontfiles():
            key = self.get_adobe_key() if self.get_encrypted_fontfiles()[
                                              uri] == ADOBE_OBFUSCATION else self.get_idpf_key()
            font_data = self.decrypt_font_data(key, font_data, self.get_encrypted_fontfiles()[uri])
        return font_data

    def decrypt_font_data(self, key, data, algorithm):
        is_adobe = algorithm == ADOBE_OBFUSCATION
        crypt_len = 1024 if is_adobe else 1040
        crypt = bytearray(data[:crypt_len])
        key = cycle(iter(bytearray(key)))
        decrypt = bytes(bytearray(x ^ next(key) for x in crypt))
        return decrypt + data[crypt_len:]



def cond_print(flag, arg):
    if flag:
        logger.debug(arg)


imagetypes = {
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'svg': 'image/svg+xml',
}


def doMerge(outputio, files,
            authoropts=[],
            titleopt=None,
            descopt=None,
            tags=[],
            languages=['en'],
            titlenavpoints=True,
            originalnavpoints=True,
            keepsingletocs=False,
            flattentoc=False,
            printtimes=False,
            coverjpgpath=None,
            keepmetadatafiles=False,
            source=None,
            notify_progress=lambda x: x):
    notify_progress(0.0)  # sets overall progress to 50%
    printt = partial(cond_print, printtimes)

    filecount = 0
    t = time()
    outputepub = ZipFile(outputio, "w", compression=ZIP_STORED, allowZip64=True)
    outputepub.debug = 3
    outputepub.writestr("mimetype", "application/epub+zip")
    outputepub.close()
    outputepub = ZipFile(outputio, "a", compression=ZIP_DEFLATED, allowZip64=True)
    outputepub.debug = 3

    containerdom = getDOMImplementation().createDocument(None, "container", None)
    containertop = containerdom.documentElement
    containertop.setAttribute("version", "1.0")
    containertop.setAttribute("xmlns", "urn:oasis:names:tc:opendocument:xmlns:container")
    rootfiles = containerdom.createElement("rootfiles")
    containertop.appendChild(rootfiles)
    rootfiles.appendChild(newTag(containerdom, "rootfile", {"full-path": "content.opf",
                                                            "media-type": "application/oebps-package+xml"}))
    outputepub.writestr("META-INF/container.xml", containerdom.toprettyxml(indent='   ', encoding='utf-8'))

    ## Process input epubs.

    items = []  # list of (id, href, type) tuples(all strings) -- From .opfs' manifests
    items.append(("ncx", "toc.ncx", "application/x-dtbncx+xml"))  ## we'll generate the toc.ncx file,
    ## but it needs to be in the items manifest.
    itemrefs = []  # list of strings -- idrefs from .opfs' spines
    navmaps = []  # list of navMap DOM elements -- TOC data for each from toc.ncx files
    is_fff_epub = []  # list of t/f

    itemhrefs = {}  # hash of item[id]s to itemref[href]s -- to find true start of book(s).
    firstitemhrefs = []

    booktitles = []  # list of strings -- Each book's title
    allauthors = []  # list of lists of strings -- Each book's list of authors.
    fileasauthors = {}  # saving opf:file-as attrs on author tags.

    filelist = []

    printt("prep output:%s" % (time() - t))
    t = time()

    booknum = 1
    firstmetadom = None

    ## only set <spine page-progression-direction=X > if all input
    ## books agree and it's not empty string.
    outputpagedirs = set()

    for epub in files:
        current_epub = {}
        if epub == None: continue
        try:
            if isinstance(epub, text_type):
                current_epub['filename'] = epub
            book = "%d" % booknum
            bookdir = "%d/" % booknum
            bookid = "a%d" % booknum

            epub = ZipFile(epub, 'r')

            ## Find the .opf file.
            container = epub.read("META-INF/container.xml")
            containerdom = parseString(container)
            rootfilenodelist = containerdom.getElementsByTagNameNS("*", "rootfile")
            rootfilename = rootfilenodelist[0].getAttribute("full-path")

            ## Save the path to the .opf file--hrefs inside it are relative to it.
            relpath = get_path_part(rootfilename)

            metadom = parseString(epub.read(rootfilename))
            fontdecrypter = FontDecrypter(epub, metadom)
            # logger.debug("metadom:%s"%epub.read(rootfilename))
            if booknum == 1 and not source:
                try:
                    firstmetadom = metadom.getElementsByTagNameNS("*", "metadata")[0]
                    source = unicode(firstmetadom.getElementsByTagName("dc:source")[0].firstChild.data)
                except:
                    source = ""

            is_fff_epub.append(False)
            ## looking for any of:
            ##   <dc:contributor id="id-2">FanFicFare [https://github.com/JimmXinu/FanFicFare]</dc:contributor>
            ##   <dc:identifier opf:scheme="FANFICFARE-UID">test1.com-u98765-s68</dc:identifier>
            ##   <dc:identifier id="fanficfare-uid">fanficfare-uid:test1.com-u98765-s68</dc:identifier>
            ## FFF writes dc:contributor and dc:identifier
            ## Sigil changes the unique-identifier, but leaves dc:contributor
            ## Calibre epub3->epub2 convert changes dc:contributor and modifies dc:identifier
            for c in metadom.getElementsByTagName("dc:contributor") + metadom.getElementsByTagName("dc:identifier"):
                # logger.debug("dc:contributor/identifier:%s"%getText(c.childNodes))
                # logger.debug("dc:contributor/identifier:%s / %s"%(c.getAttribute('opf:scheme'),c.getAttribute('id')))
                if (getText(c.childNodes) in ["fanficdownloader [http://fanficdownloader.googlecode.com]",
                                              "FanFicFare [https://github.com/JimmXinu/FanFicFare]"]
                        or 'fanficfare-uid' in c.getAttribute('opf:scheme').lower()
                        or 'fanficfare-uid' in c.getAttribute('id').lower()):
                    # logger.debug("------------> is_fff_epub <-----------------")
                    is_fff_epub[-1] = True  # set last.
                    break;

            ## Save indiv book title
            try:
                booktitles.append(metadom.getElementsByTagName("dc:title")[0].firstChild.data)
            except:
                booktitles.append("(Title Missing)")
            current_epub['title'] = booktitles[-1]

            ## Save authors.
            authors = []
            for creator in metadom.getElementsByTagName("dc:creator"):
                try:
                    if (creator.getAttribute("opf:role") == "aut" or not creator.hasAttribute(
                            "opf:role") and creator.firstChild != None):
                        authors.append(creator.firstChild.data)
                        if creator.getAttribute("opf:file-as"):
                            fileasauthors[creator.firstChild.data] = creator.getAttribute("opf:file-as")
                except:
                    pass
            if len(authors) == 0:
                authors.append("(Author Missing)")
            allauthors.append(authors)
            current_epub['authors'] = authors

            ## Record input page dir.
            outputpagedirs.add(metadom.getElementsByTagName("spine")[0].getAttribute("page-progression-direction"))

            if keepmetadatafiles:
                itemid = bookid + "rootfile"
                itemhref = rootfilename
                href = normpath(bookdir + itemhref)
                logger.debug("write rootfile %s to %s" % (itemhref, href))
                outputepub.writestr(href,
                                    epub.read(itemhref))
                items.append((itemid, href, "origrootfile/xml"))

            # spin through the manifest--only place there are item tags.
            # Correction--only place there *should* be item tags.  But
            # somebody found one that did.
            manifesttag = metadom.getElementsByTagNameNS("*", "manifest")[0]
            for item in manifesttag.getElementsByTagNameNS("*", "item"):
                itemid = bookid + item.getAttribute("id")
                itemhref = normpath(unquote(item.getAttribute("href")))  # remove %20, etc.
                href = normpath(bookdir + relpath + itemhref)  # normpath for ..
                # if item.getAttribute("properties") == "nav":
                #     # epub3 TOC file is only one with this type--as far as I know.
                #     # grab the whole navmap, deal with it later.
                # el
                if item.getAttribute("media-type") == "application/x-dtbncx+xml":
                    # epub2 TOC file is only one with this type--as far as I know.
                    # grab the whole navmap, deal with it later.
                    tocdom = parseString(epub.read(normpath(relpath + item.getAttribute("href"))))

                    # update all navpoint ids with bookid for uniqueness.
                    for navpoint in tocdom.getElementsByTagNameNS("*", "navPoint"):
                        navpoint.setAttribute("id", bookid + navpoint.getAttribute("id"))

                    # update all content paths with bookdir for uniqueness.
                    for content in tocdom.getElementsByTagNameNS("*", "content"):
                        content.setAttribute("src", normpath(bookdir + relpath + content.getAttribute("src")))

                    if len(navmaps) == booknum:
                        logger.warning(
                            "More than one application/x-dtbncx+xml (toc.ncx) file found, using last to match Calibre viewer")
                        navmaps[-1] = tocdom.getElementsByTagNameNS("*", "navMap")[0]
                    else:
                        navmaps.append(tocdom.getElementsByTagNameNS("*", "navMap")[0])

                    if keepmetadatafiles:
                        logger.debug("write toc.ncx %s to %s" % (relpath + itemhref, href))
                        outputepub.writestr(href,
                                            epub.read(normpath(relpath + itemhref)))
                        items.append((itemid, href, "origtocncx/xml"))
                else:
                    # href=href.encode('utf8')
                    # logger.debug("item id: %s -> %s:"%(itemid,href))
                    itemhrefs[itemid] = href
                    if href not in filelist:
                        try:
                            # logger.debug("read href:%s"%normpath(relpath+itemhref))
                            filedata = epub.read(normpath(relpath + itemhref))
                            if normpath(relpath + itemhref) in fontdecrypter.get_encrypted_fontfiles():
                                logger.info("Decrypting font file: %s" % itemhref)
                                filedata = fontdecrypter.get_decrypted_font_data(normpath(relpath + itemhref))
                            outputepub.writestr(href, filedata)
                            if re.match(r'.*/(file|chapter)\d+\.x?html', href):
                                filecount += 1
                            items.append((itemid, href, item.getAttribute("media-type")))
                            filelist.append(href)
                        except KeyError as ke:  # Skip missing files.
                            logger.info("Skipping missing file %s (%s)" % (href, relpath + itemhref))
                            del itemhrefs[itemid]

            itemreflist = metadom.getElementsByTagNameNS("*", "itemref")
            # logger.debug("itemhrefs:%s"%itemhrefs)
            logger.debug("bookid:%s" % bookid)
            logger.debug("itemreflist[0].getAttribute(idref):%s" % itemreflist[0].getAttribute("idref"))

            # Looking for the first item in itemreflist that wasn't
            # discarded due to missing files.
            for itemref in itemreflist:
                idref = bookid + itemref.getAttribute("idref")
                if idref in itemhrefs:
                    firstitemhrefs.append(itemhrefs[idref])
                    break

            for itemref in itemreflist:
                itemrefs.append(bookid + itemref.getAttribute("idref"))
                # logger.debug("adding to itemrefs:\n%s"%itemref.toprettyxml())

            notify_progress(float(booknum - 1) / len(files))
            booknum = booknum + 1;

        except:
            print("\nError occurred processing '%s' by %s.\nTemp file left in %s\n" % (
                current_epub.get('title', 'Unknown'),
                current_epub.get('authors', 'Unknown'),
                current_epub.get('filename', 'Unknown')))
            raise
        # print(current_epub)

    printt("after file loop:%s" % (time() - t))
    t = time()

    ## create content.opf file.
    uniqueid = "epubmerge-uid-%d" % time()  # real sophisticated uid scheme.
    contentdom = getDOMImplementation().createDocument(None, "package", None)
    package = contentdom.documentElement

    package.setAttribute("version", "2.0")
    package.setAttribute("xmlns", "http://www.idpf.org/2007/opf")
    package.setAttribute("unique-identifier", "epubmerge-id")
    metadata = newTag(contentdom, "metadata",
                      attrs={"xmlns:dc": "http://purl.org/dc/elements/1.1/",
                             "xmlns:opf": "http://www.idpf.org/2007/opf"})
    metadata.appendChild(newTag(contentdom, "dc:identifier", text=uniqueid, attrs={"id": "epubmerge-id"}))
    if (titleopt is None):
        titleopt = booktitles[0] + " Anthology"
    metadata.appendChild(newTag(contentdom, "dc:title", text=titleopt))

    # If cmdline authors, use those instead of those collected from the epubs
    # (allauthors kept for TOC & description gen below.
    if (len(authoropts) > 1):
        useauthors = [authoropts]
        fileasauthors = {}  # don't use opf:file-as attrs when taking authors from CLI opts.
    else:
        useauthors = allauthors

    usedauthors = dict()
    for authorlist in useauthors:
        for author in authorlist:
            if (author not in usedauthors):
                usedauthors[author] = author
                tagattrs = {"opf:role": "aut"}
                if fileasauthors.get(author, None):
                    tagattrs["opf:file-as"] = fileasauthors[author]
                metadata.appendChild(newTag(contentdom, "dc:creator",
                                            attrs=tagattrs,
                                            text=author))

    metadata.appendChild(newTag(contentdom, "dc:contributor", text="epubmerge"))
    metadata.appendChild(newTag(contentdom, "dc:rights", text="Copyrights as per source stories"))

    for l in languages:
        metadata.appendChild(newTag(contentdom, "dc:language", text=l))

    if not descopt:
        # created now, but not filled in until TOC generation to save loops.
        description = newTag(contentdom, "dc:description", text="Anthology containing:\n")
    else:
        description = newTag(contentdom, "dc:description", text=descopt)
    metadata.appendChild(description)

    if source:
        metadata.appendChild(newTag(contentdom, "dc:identifier",
                                    attrs={"opf:scheme": "URL"},
                                    text=source))
        metadata.appendChild(newTag(contentdom, "dc:source",
                                    text=source))

    for tag in tags:
        metadata.appendChild(newTag(contentdom, "dc:subject", text=tag))

    package.appendChild(metadata)

    manifest = contentdom.createElement("manifest")
    package.appendChild(manifest)

    spine = newTag(contentdom, "spine", attrs={"toc": "ncx"})
    if len(outputpagedirs) == 1:
        ## all books had the same page-progression-direction value.
        pagedir = outputpagedirs.pop()
        if pagedir:
            ## ...and it's not empty string.
            logger.debug("Setting <spine page-progression-direction='%s'>" % pagedir)
            spine.setAttribute("page-progression-direction", pagedir)
    else:
        logger.debug("<spine page-progression-direction attrs didn't all match %s, ignoring." % outputpagedirs)
    package.appendChild(spine)

    if coverjpgpath:
        # in case coverjpg isn't a jpg:
        coverext = 'jpg'
        covertype = 'image/jpeg'
        try:
            coverext = coverjpgpath.split('.')[-1].lower()
            covertype = imagetypes.get(coverext, covertype)
        except:
            pass
        logger.debug("coverjpgpath:%s coverext:%s covertype:%s" % (coverjpgpath, coverext, covertype))
        # <meta name="cover" content="cover.jpg"/>
        metadata.appendChild(newTag(contentdom, "meta", {"name": "cover",
                                                         "content": "coverimageid"}))
        guide = newTag(contentdom, "guide")
        guide.appendChild(newTag(contentdom, "reference", attrs={"type": "cover",
                                                                 "title": "Cover",
                                                                 "href": "cover.xhtml"}))
        package.appendChild(guide)

        manifest.appendChild(newTag(contentdom, "item",
                                    attrs={'id': "coverimageid",
                                           'href': "cover." + coverext,
                                           'media-type': covertype}))

        # Note that the id of the cover xhmtl *must* be 'cover'
        # for it to work on Nook.
        manifest.appendChild(newTag(contentdom, "item",
                                    attrs={'id': "cover",
                                           'href': "cover.xhtml",
                                           'media-type': "application/xhtml+xml"}))

        spine.appendChild(newTag(contentdom, "itemref",
                                 attrs={"idref": "cover",
                                        "linear": "yes"}))

    for item in items:
        # logger.debug("new item:%s %s %s"%item)
        (id, href, type) = item
        manifest.appendChild(newTag(contentdom, "item",
                                    attrs={'id': id,
                                           'href': href,
                                           'media-type': type}))

    for itemref in itemrefs:
        # logger.debug("itemref:%s"%itemref)
        spine.appendChild(newTag(contentdom, "itemref",
                                 attrs={"idref": itemref,
                                        "linear": "yes"}))

    ## create toc.ncx file
    tocncxdom = getDOMImplementation().createDocument(None, "ncx", None)
    ncx = tocncxdom.documentElement
    ncx.setAttribute("version", "2005-1")
    ncx.setAttribute("xmlns", "http://www.daisy.org/z3986/2005/ncx/")
    head = tocncxdom.createElement("head")
    ncx.appendChild(head)
    head.appendChild(newTag(tocncxdom, "meta",
                            attrs={"name": "dtb:uid", "content": uniqueid}))
    depthnode = newTag(tocncxdom, "meta",
                       attrs={"name": "dtb:depth", "content": "4"})
    head.appendChild(depthnode)
    head.appendChild(newTag(tocncxdom, "meta",
                            attrs={"name": "dtb:totalPageCount", "content": "0"}))
    head.appendChild(newTag(tocncxdom, "meta",
                            attrs={"name": "dtb:maxPageNumber", "content": "0"}))

    docTitle = tocncxdom.createElement("docTitle")
    docTitle.appendChild(newTag(tocncxdom, "text", text=titleopt))
    ncx.appendChild(docTitle)

    tocnavMap = tocncxdom.createElement("navMap")
    ncx.appendChild(tocnavMap)

    booknum = 0

    printt("wrote initial metadata:%s" % (time() - t))
    t = time()

    for navmap in navmaps:

        # logger.debug( [ x.toprettyxml() for x in navmap.childNodes ] )
        ## only gets top level TOC entries.  sub entries carried inside.
        navpoints = [x for x in navmap.childNodes if isinstance(x, Element) and x.tagName == "navPoint"]
        # logger.debug("len(navpoints):%s"%len(navpoints))
        # logger.debug( [ x.toprettyxml() for x in navpoints ] )
        newnav = None
        if titlenavpoints:
            newnav = newTag(tocncxdom, "navPoint", {"id": "book%03d" % booknum})
            navlabel = newTag(tocncxdom, "navLabel")
            newnav.appendChild(navlabel)
            # For purposes of TOC titling & desc, use first book author.  Skip adding author if only one.
            if len(usedauthors) > 1:
                title = booktitles[booknum] + " by " + allauthors[booknum][0]
            else:
                title = booktitles[booknum]

            navlabel.appendChild(newTag(tocncxdom, "text", text=title))
            # Find the first 'spine' item's content for the title navpoint.
            # Many epubs have the first chapter as first navpoint, so we can't just
            # copy that anymore.
            newnav.appendChild(newTag(tocncxdom, "content",
                                      {"src": firstitemhrefs[booknum]}))

            # logger.debug("newnav:\n%s"%newnav.toprettyxml())
            tocnavMap.appendChild(newnav)
            # logger.debug("tocnavMap:\n%s"%tocnavMap.toprettyxml())
        else:
            newnav = tocnavMap

        if not descopt and len(allauthors[booknum]) > 0:
            description.appendChild(
                contentdom.createTextNode(booktitles[booknum] + " by " + allauthors[booknum][0] + "\n"))

        depthnavpoints = navmap.getElementsByTagNameNS("*", "navPoint")  # for checking more than one TOC entry
        ## If including original TOCs AND adding book title TOCs AND
        ## EITHER keep single toc option OR more than one TOC
        ## point(total, not top level), include sub book TOC entries.
        ## Each navpoint may be a whole sub tree.
        if originalnavpoints and titlenavpoints and (keepsingletocs or len(depthnavpoints) > 1):
            if not is_fff_epub[booknum]:
                nonskip_navpoints_count = len(depthnavpoints)
            else:
                ## For FFF epubs ONLY, count chapters skipping log
                ## and/or title pages
                nonskip_navpoints_count = 0
                for navpoint in navpoints:
                    # logger.debug("navpoint:\n%s"%navpoint.toprettyxml())

                    # this isn't going to find title/log pages farther
                    # down a tree, but if it's truly FFF input, they
                    # should be at this level.
                    contentsrc = ''
                    navpointid = ''
                    for n in navpoint.childNodes:
                        if isinstance(n, Element) and n.tagName == "content":
                            contentsrc = n.getAttribute("src")
                            break
                    navpointid = navpoint.getAttribute("id")
                    # logger.debug("navpointid:%s"%navpointid)
                    # logger.debug("contentsrc:%s"%contentsrc)

                    if not (navpointid.endswith('log_page') or
                            contentsrc.endswith("log_page.xhtml") or
                            navpointid.endswith('title_page') or
                            contentsrc.endswith("title_page.xhtml")):
                        # logger.debug("nonskip")
                        ## 1 for this node, plus search down for nested
                        nonskip_navpoints_count += (1 + len(navpoint.getElementsByTagNameNS("*", "navPoint")))
                    # logger.debug("nonskip_navpoints_count:%s"%nonskip_navpoints_count)

            if keepsingletocs or nonskip_navpoints_count > 1:
                for navpoint in navpoints:
                    # logger.debug("include navpoint:\n%s"%navpoint.toprettyxml())
                    newnav.appendChild(navpoint)

        booknum = booknum + 1;
        # end of navmaps loop.

    maxdepth = 0
    contentsrcs = {}
    removednodes = []
    ## Force strict ordering of playOrder, stripping out some.
    playorder = 0
    # logger.debug("tocncxdom:\n%s"%tocncxdom.toprettyxml())
    for navpoint in tocncxdom.getElementsByTagNameNS("*", "navPoint"):
        # logger.debug("navpoint:\n%s"%navpoint.toprettyxml())
        if navpoint in removednodes:
            continue
        # need content[src] to compare for dups.  epub wants dup srcs to have same playOrder.
        contentsrc = None
        for n in navpoint.childNodes:
            if isinstance(n, Element) and n.tagName == "content":
                contentsrc = n.getAttribute("src")
                # logger.debug("contentsrc: %s"%contentsrc)
                break

        if (contentsrc not in contentsrcs):
            parent = navpoint.parentNode

            # New src, new number.
            contentsrcs[contentsrc] = navpoint.getAttribute("id")
            playorder += 1
            navpoint.setAttribute("playOrder", "%d" % playorder)
            # logger.debug("playorder:%d:"%playorder)

            # need to know depth of deepest navpoint for <meta name="dtb:depth" content="2"/>
            npdepth = 1
            dp = navpoint.parentNode
            while dp and dp.tagName != "navMap":
                npdepth += 1
                dp = dp.parentNode

            if npdepth > maxdepth:
                maxdepth = npdepth
        else:
            # easier to just set it now, even if the node gets removed later.
            navpoint.setAttribute("playOrder", "%d" % playorder)
            logger.debug("playorder:%d:" % playorder)
            parent = navpoint.parentNode

    if flattentoc:
        maxdepth = 1
        # already have play order and pesky dup/single chapters
        # removed, just need to flatten.
        flattocnavMap = tocncxdom.createElement("navMap")
        for n in tocnavMap.getElementsByTagNameNS("*", "navPoint"):
            flattocnavMap.appendChild(n)

        ncx.replaceChild(flattocnavMap, tocnavMap)

    printt("navmap/toc maddess:%s" % (time() - t))
    t = time()

    depthnode.setAttribute("content", "%d" % maxdepth)

    ## content.opf written now due to description being filled in
    ## during TOC generation to save loops.
    contentxml = contentdom.toprettyxml(indent='   ', encoding='utf-8')
    # tweak for brain damaged Nook STR.  Nook insists on name before content.
    contentxml = contentxml.replace(ensure_binary('<meta content="coverimageid" name="cover"/>'),
                                    ensure_binary('<meta name="cover" content="coverimageid"/>'))
    outputepub.writestr("content.opf", contentxml)
    outputepub.writestr("toc.ncx", tocncxdom.toprettyxml(indent='   ', encoding='utf-8'))

    printt("wrote opf/ncx files:%s" % (time() - t))
    t = time()

    if coverjpgpath:
        # write, not write string.  Pulling from file.
        outputepub.write(coverjpgpath, "cover." + coverext)

        outputepub.writestr("cover.xhtml", '''
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en"><head><title>Cover</title><style type="text/css" title="override_css">
@page {padding: 0pt; margin:0pt}
body { text-align: center; padding:0pt; margin: 0pt; }
div { margin: 0pt; padding: 0pt; }
</style></head><body><div>
<img src="cover.''' + coverext + '''" alt="cover"/>
</div></body></html>
''')

    # declares all the files created by Windows.  otherwise, when
    # it runs in appengine, windows unzips the files as 000 perms.
    for zf in outputepub.filelist:
        zf.create_system = 0
    outputepub.close()



def get_path_part(n):
    relpath = os.path.dirname(n)
    if (len(relpath) > 0):
        relpath = relpath + "/"
    return relpath


def newTag(dom, name, attrs=None, text=None):
    tag = dom.createElement(name)
    if (attrs is not None):
        for attr in attrs.keys():
            tag.setAttribute(attr, attrs[attr])
    if (text is not None):
        tag.appendChild(dom.createTextNode(unicode(text)))
    return tag


def getText(nodelist):
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.data)
    return ''.join(rc)

