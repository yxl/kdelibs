/* This file is part of the KDE project
   Copyright (C) 1998-2009 David Faure <faure@kde.org>
                 2003      Sven Leiber <s.leiber@web.de>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 or at your option version 3.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this library; see the file COPYING.LIB.  If not, write to
   the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/

#include "knewfilemenu.h"
#include "knameandurlinputdialog.h"

#include <QDir>
#include <QVBoxLayout>
#include <QList>
#include <kactioncollection.h>
#include <kdebug.h>
#include <kdesktopfile.h>
#include <kdirwatch.h>
#include <kicon.h>
#include <kcomponentdata.h>
#include <kinputdialog.h>
#include <klocale.h>
#include <kmessagebox.h>
#include <kstandarddirs.h>
#include <kprotocolinfo.h>
#include <kprotocolmanager.h>
#include <kmenu.h>
#include <krun.h>
#include <kshell.h>
#include <kio/job.h>
#include <kio/copyjob.h>
#include <kio/jobuidelegate.h>
#include <kio/renamedialog.h>
#include <kio/netaccess.h>
#include <kio/fileundomanager.h>

#include <kpropertiesdialog.h>
#include <ktemporaryfile.h>
#include <utime.h>

// Singleton, with data shared by all KNewFileMenu instances
class KNewFileMenuSingleton
{
public:
    KNewFileMenuSingleton()
        : templatesList(0),
          templatesVersion(0),
          filesParsed(false),
          dirWatch(0)
    {
    }
    ~KNewFileMenuSingleton()
    {
        delete templatesList;
        delete dirWatch;
    }


    /**
     * Opens the desktop files and completes the Entry list
     * Input: the entry list. Output: the entry list ;-)
     */
    void parseFiles();

    /**
     * For entryType
     * LINKTOTEMPLATE: a desktop file that points to a file or dir to copy
     * TEMPLATE: a real file to copy as is (the KDE-1.x solution)
     * SEPARATOR: to put a separator in the menu
     * 0 means: not parsed, i.e. we don't know
     */
    enum EntryType { Unknown, LinkToTemplate = 1, Template, Separator };

    struct Entry {
        QString text;
        QString filePath; // empty for Separator
        QString templatePath; // same as filePath for Template
        QString icon;
        EntryType entryType;
        QString comment;
        QString mimeType;
    };
    // NOTE: only filePath is known before we call parseFiles

    /**
     * List of all template files. It is important that they are in
     * the same order as the 'New' menu.
     */
    typedef QList<Entry> EntryList;
    EntryList * templatesList;

    /**
     * Is increased when templatesList has been updated and
     * menu needs to be re-filled. Menus have their own version and compare it
     * to templatesVersion before showing up
     */
    int templatesVersion;

    /**
     * Set back to false each time new templates are found,
     * and to true on the first call to parseFiles
     */
    bool filesParsed;
    KDirWatch * dirWatch;
};

K_GLOBAL_STATIC(KNewFileMenuSingleton, kNewMenuGlobals)

class KNewFileMenuPrivate
{
public:
    KNewFileMenuPrivate(KNewFileMenu* qq)
        : m_menuItemsVersion(0),
          m_viewShowsHiddenFiles(false),
          q(qq)
    {}

    /**
     * Fills the menu from the templates list.
     */
    void fillMenu();

    /**
     * Called when New->* is clicked
     */
    void _k_slotActionTriggered(QAction*);

    /**
     * Fills the templates list.
     */
    void _k_slotFillTemplates();

    KActionCollection * m_actionCollection;
    QWidget *m_parentWidget;
    KActionMenu *m_menuDev;
    QAction* m_newDirAction;

    int m_menuItemsVersion;
    bool m_viewShowsHiddenFiles;

    /**
     * When the user pressed the right mouse button over an URL a popup menu
     * is displayed. The URL belonging to this popup menu is stored here.
     */
    KUrl::List m_popupFiles;

    QStringList m_supportedMimeTypes;

    QString m_tempFileToDelete; // set when a tempfile was created for a Type=URL desktop file

    /**
     * The action group that our actions belong to
     */
    QActionGroup* m_newMenuGroup;
    KNewFileMenu* q;

    class StrategyInterface;
    class UrlDesktopFileStrategy;
    class SymLinkStrategy;
    class OtherDesktopFileStrategy;
    class RealFileOrDirStrategy;
};

KNewFileMenu::KNewFileMenu(KActionCollection* collection, const QString& name, QWidget* parent)
    : KActionMenu(KIcon("document-new"), i18n("Create New"), parent),
      d(new KNewFileMenuPrivate(this))
{
    // Don't fill the menu yet
    // We'll do that in checkUpToDate (should be connected to aboutToShow)
    d->m_newMenuGroup = new QActionGroup(this);
    connect(d->m_newMenuGroup, SIGNAL(triggered(QAction*)), this, SLOT(_k_slotActionTriggered(QAction*)));
    d->m_actionCollection = collection;
    d->m_parentWidget = parent;
    d->m_newDirAction = 0;

    d->m_actionCollection->addAction(name, this);

    d->m_menuDev = new KActionMenu(KIcon("drive-removable-media"), i18n("Link to Device"), this);
}

KNewFileMenu::~KNewFileMenu()
{
    //kDebug(1203) << this;
    delete d;
}

void KNewFileMenu::checkUpToDate()
{
    KNewFileMenuSingleton* s = kNewMenuGlobals;
    //kDebug(1203) << this << "m_menuItemsVersion=" << d->m_menuItemsVersion
    //              << "s->templatesVersion=" << s->templatesVersion;
    if (d->m_menuItemsVersion < s->templatesVersion || s->templatesVersion == 0) {
        //kDebug(1203) << "recreating actions";
        // We need to clean up the action collection
        // We look for our actions using the group
        foreach (QAction* action, d->m_newMenuGroup->actions())
            delete action;

        if (!s->templatesList) { // No templates list up to now
            s->templatesList = new KNewFileMenuSingleton::EntryList;
            d->_k_slotFillTemplates();
            s->parseFiles();
        }

        // This might have been already done for other popupmenus,
        // that's the point in s->filesParsed.
        if (!s->filesParsed) {
            s->parseFiles();
        }

        d->fillMenu();

        d->m_menuItemsVersion = s->templatesVersion;
    }
}

void KNewFileMenuSingleton::parseFiles()
{
    //kDebug(1203);
    filesParsed = true;
    KNewFileMenuSingleton::EntryList::iterator templ = templatesList->begin();
    const KNewFileMenuSingleton::EntryList::iterator templ_end = templatesList->end();
    for (; templ != templ_end; ++templ)
    {
        QString iconname;
        QString filePath = (*templ).filePath;
        if (!filePath.isEmpty())
        {
            QString text;
            QString templatePath;
            // If a desktop file, then read the name from it.
            // Otherwise (or if no name in it?) use file name
            if (KDesktopFile::isDesktopFile(filePath)) {
                KDesktopFile desktopFile( filePath);
                text = desktopFile.readName();
                (*templ).icon = desktopFile.readIcon();
                (*templ).comment = desktopFile.readComment();
                QString type = desktopFile.readType();
                if (type == "Link")
                {
                    templatePath = desktopFile.desktopGroup().readPathEntry("URL", QString());
                    if (templatePath[0] != '/' && !templatePath.startsWith("__"))
                    {
                        if (templatePath.startsWith("file:/"))
                            templatePath = KUrl(templatePath).toLocalFile();
                        else
                        {
                            // A relative path, then (that's the default in the files we ship)
                            QString linkDir = filePath.left(filePath.lastIndexOf('/') + 1 /*keep / */);
                            //kDebug(1203) << "linkDir=" << linkDir;
                            templatePath = linkDir + templatePath;
                        }
                    }
                }
                if (templatePath.isEmpty())
                {
                    // No URL key, this is an old-style template
                    (*templ).entryType = KNewFileMenuSingleton::Template;
                    (*templ).templatePath = (*templ).filePath; // we'll copy the file
                } else {
                    (*templ).entryType = KNewFileMenuSingleton::LinkToTemplate;
                    (*templ).templatePath = templatePath;
                }

            }
            if (text.isEmpty())
            {
                text = KUrl(filePath).fileName();
                if (text.endsWith(".desktop"))
                    text.truncate(text.length() - 8);
            }
            (*templ).text = text;
            /*kDebug(1203) << "Updating entry with text=" << text
                          << "entryType=" << (*templ).entryType
                          << "templatePath=" << (*templ).templatePath;*/
        }
        else {
            (*templ).entryType = KNewFileMenuSingleton::Separator;
        }
    }
}

void KNewFileMenuPrivate::fillMenu()
{
    QMenu* menu = q->menu();
    menu->clear();
    m_menuDev->menu()->clear();
    m_newDirAction = 0;

    QSet<QString> seenTexts;
    // these shall be put at special positions
    QAction* linkURL = 0;
    QAction* linkApp = 0;
    QAction* linkPath = 0;

    KNewFileMenuSingleton* s = kNewMenuGlobals;
    int i = 1;
    KNewFileMenuSingleton::EntryList::iterator templ = s->templatesList->begin();
    const KNewFileMenuSingleton::EntryList::iterator templ_end = s->templatesList->end();
    for (; templ != templ_end; ++templ, ++i)
    {
        KNewFileMenuSingleton::Entry& entry = *templ;
        if (entry.entryType != KNewFileMenuSingleton::Separator) {
            // There might be a .desktop for that one already, if it's a kdelnk
            // This assumes we read .desktop files before .kdelnk files ...

            // In fact, we skip any second item that has the same text as another one.
            // Duplicates in a menu look bad in any case.

            const bool bSkip = seenTexts.contains(entry.text);
            if (bSkip) {
                kDebug(1203) << "skipping" << entry.filePath;
            } else {
                seenTexts.insert(entry.text);
                //const KNewFileMenuSingleton::Entry entry = templatesList->at(i-1);

                const QString templatePath = entry.templatePath;
                // The best way to identify the "Create Directory", "Link to Location", "Link to Application" was the template
                if (templatePath.endsWith("emptydir")) {
                    QAction * act = new QAction(q);
                    m_newDirAction = act;
                    act->setIcon(KIcon(entry.icon));
                    act->setText(entry.text);
                    act->setActionGroup(m_newMenuGroup);
                    menu->addAction(act);

                    QAction *sep = new QAction(q);
                    sep->setSeparator(true);
                    menu->addAction(sep);
                } else {

                    if (!m_supportedMimeTypes.isEmpty()) {
                        bool keep = false;

                        // We need to do mimetype filtering, for real files.
                        const bool createSymlink = entry.templatePath == "__CREATE_SYMLINK__";
                        if (createSymlink) {
                            keep = true;
                        } else if (!KDesktopFile::isDesktopFile(entry.templatePath)) {

                            // Determine mimetype on demand
                            KMimeType::Ptr mime;
                            if (entry.mimeType.isEmpty()) {
                                mime = KMimeType::findByPath(entry.templatePath);
                                if (mime) {
                                    //kDebug() << entry.templatePath << "is" << mime->name();
                                    entry.mimeType = mime->name();
                                } else {
                                    entry.mimeType = KMimeType::defaultMimeType();
                                }
                            } else {
                                mime = KMimeType::mimeType(entry.mimeType);
                            }
                            Q_FOREACH(const QString& supportedMime, m_supportedMimeTypes) {
                                if (mime && mime->is(supportedMime)) {
                                    keep = true;
                                    break;
                                }
                            }
                        }

                        if (!keep) {
                            //kDebug() << "Not keeping" << entry.templatePath;
                            continue;
                        }
                    }

                    QAction * act = new QAction(q);
                    act->setData(i);
                    act->setIcon(KIcon(entry.icon));
                    act->setText(entry.text);
                    act->setActionGroup(m_newMenuGroup);

                    //kDebug() << templatePath << entry.filePath;

                    if (templatePath.endsWith("/URL.desktop")) {
                        linkURL = act;
                    } else if (templatePath.endsWith("/Program.desktop")) {
                        linkApp = act;
                    } else if (entry.filePath.endsWith("/linkPath.desktop")) {
                        linkPath = act;
                    } else if (KDesktopFile::isDesktopFile(templatePath)) {
                        KDesktopFile df(templatePath);
                        if (df.readType() == "FSDevice")
                            m_menuDev->menu()->addAction(act);
                        else
                            menu->addAction(act);
                    }
                    else
                    {
                        menu->addAction(act);
                    }
                }
            }
        } else { // Separate system from personal templates
            Q_ASSERT(entry.entryType != 0);

            QAction *sep = new QAction(q);
            sep->setSeparator(true);
            menu->addAction(sep);
        }
    }

    if (m_supportedMimeTypes.isEmpty()) {
        QAction *sep = new QAction(q);
        sep->setSeparator(true);
        menu->addAction(sep);
        if (linkURL) menu->addAction(linkURL);
        if (linkPath) menu->addAction(linkPath);
        if (linkApp) menu->addAction(linkApp);
        Q_ASSERT(m_menuDev);
        menu->addAction(m_menuDev);
    }
}

void KNewFileMenuPrivate::_k_slotFillTemplates()
{
    KNewFileMenuSingleton* s = kNewMenuGlobals;
    //kDebug(1203);
    // Ensure any changes in the templates dir will call this
    if (! s->dirWatch) {
        s->dirWatch = new KDirWatch;
        const QStringList dirs = m_actionCollection->componentData().dirs()->resourceDirs("templates");
        for (QStringList::const_iterator it = dirs.constBegin() ; it != dirs.constEnd() ; ++it) {
            //kDebug(1203) << "Templates resource dir:" << *it;
            s->dirWatch->addDir(*it);
        }
        QObject::connect(s->dirWatch, SIGNAL(dirty(const QString &)),
                         q, SLOT(_k_slotFillTemplates()));
        QObject::connect(s->dirWatch, SIGNAL(created(const QString &)),
                         q, SLOT(_k_slotFillTemplates()));
        QObject::connect(s->dirWatch, SIGNAL(deleted(const QString &)),
                         q, SLOT(_k_slotFillTemplates()));
        // Ok, this doesn't cope with new dirs in KDEDIRS, but that's another story
    }
    ++s->templatesVersion;
    s->filesParsed = false;

    s->templatesList->clear();

    // Look into "templates" dirs.
    const QStringList files = m_actionCollection->componentData().dirs()->findAllResources("templates");
    QMap<QString, KNewFileMenuSingleton::Entry> slist; // used for sorting
    Q_FOREACH(const QString& file, files) {
        //kDebug(1203) << file;
        if (file[0] != '.') {
            KNewFileMenuSingleton::Entry e;
            e.filePath = file;
            e.entryType = KNewFileMenuSingleton::Unknown; // not parsed yet

            // Put Directory first in the list (a bit hacky),
            // and TextFile before others because it's the most used one.
            // This also sorts by user-visible name.
            // The rest of the re-ordering is done in fillMenu.
            const KDesktopFile config(file);
            QString key = config.desktopGroup().readEntry("Name");
            if (file.endsWith("Directory.desktop")) {
                key.prepend('0');
            } else if (file.endsWith("TextFile.desktop")) {
                key.prepend('1');
            } else {
                key.prepend('2');
            }
            slist.insert(key, e);
        }
    }
    (*s->templatesList) += slist.values();
}

// Duplicated in libkonq's KonqOperations
static bool confirmCreatingHiddenDir(const QString& name, QWidget* parent)
{
    KGuiItem continueGuiItem(KStandardGuiItem::cont());
    continueGuiItem.setText(i18nc("@action:button", "Create directory"));
    KGuiItem cancelGuiItem(KStandardGuiItem::cancel());
    cancelGuiItem.setText(i18nc("@action:button", "Enter a different name"));
    return KMessageBox::warningContinueCancel(
        parent,
        i18n("The name \"%1\" starts with a dot, so the directory will be hidden by default.", name),
        i18n("Create hidden directory?"),
        continueGuiItem,
        cancelGuiItem,
        "confirm_create_hidden_dir") == KMessageBox::Continue;
}

void KNewFileMenu::createDirectory()
{
    if (d->m_popupFiles.isEmpty())
       return;

    KUrl baseUrl = d->m_popupFiles.first();
    QString name = i18n("New Folder");
    if (baseUrl.isLocalFile() && QFileInfo(baseUrl.toLocalFile(KUrl::AddTrailingSlash) + name).exists())
        name = KIO::RenameDialog::suggestName(baseUrl, name);

    KUrl url;
    bool askAgain;
    do {
        askAgain = false;
        bool ok;
        name = KInputDialog::getText(i18n("New Folder"),
                                     i18n("Create new folder in:\n%1", baseUrl.pathOrUrl()),
                                     name, &ok, d->m_parentWidget);
        if (ok && !name.isEmpty()) {
            if ((name[0] == '/') || (name[0] == '~')) {
                url.setPath(KShell::tildeExpand(name));
            } else {
                if (!d->m_viewShowsHiddenFiles && name.startsWith('.')) {
                    if (!confirmCreatingHiddenDir(name, d->m_parentWidget)) {
                        askAgain = true;
                        continue;
                    }
                }
                name = KIO::encodeFileName( name );
                url = baseUrl;
                url.addPath( name );
            }

            KIO::SimpleJob * job = KIO::mkdir(url);
            job->setProperty("isMkdirJob", true); // KDE5: cast to MkdirJob in slotResult instead
            job->ui()->setWindow(d->m_parentWidget);
            job->ui()->setAutoErrorHandlingEnabled(true);
            KIO::FileUndoManager::self()->recordJob( KIO::FileUndoManager::Mkdir, KUrl(), url, job );

            if (job) {
                // We want the error handling to be done by slotResult so that subclasses can reimplement it
                job->ui()->setAutoErrorHandlingEnabled(false);
                connect(job, SIGNAL(result(KJob *)),
                        this, SLOT(slotResult(KJob *)));
            }

            break;
        }
    } while (askAgain);

}

class KNewFileMenuPrivate::StrategyInterface
{
public:
    void setParentWidget(QWidget* widget) { m_parentWidget = widget; }
    void setPopupFiles(const KUrl::List& urls) { m_popupUrls = urls; }

    virtual void execute(const KNewFileMenuSingleton::Entry& entry) = 0;
    virtual ~StrategyInterface() {}

    QString chosenFileName() const { return m_chosenFileName; }
    // If empty, no copy is performed.
    QString sourceFileToCopy() const { return m_src; }
    QString tempFileToDelete() const { return m_tempFileToDelete; }

    bool checkSourceExists(const QString& src);

protected:
    QWidget* m_parentWidget;
    QString m_chosenFileName;
    QString m_src;
    QString m_tempFileToDelete;
    KUrl::List m_popupUrls;
};

// The strategy used for "url" desktop files
class KNewFileMenuPrivate::UrlDesktopFileStrategy : public KNewFileMenuPrivate::StrategyInterface
{
public:
    virtual void execute(const KNewFileMenuSingleton::Entry& entry);
};

// The strategy used when creating a symlink
class KNewFileMenuPrivate::SymLinkStrategy : public KNewFileMenuPrivate::StrategyInterface
{
public:
    virtual void execute(const KNewFileMenuSingleton::Entry& entry);
};

// The strategy used for other desktop files than Type=Link. Example: Application, Device.
class KNewFileMenuPrivate::OtherDesktopFileStrategy : public KNewFileMenuPrivate::StrategyInterface
{
public:
    virtual void execute(const KNewFileMenuSingleton::Entry& entry);
};

// The strategy used for "real files or directories" (the common case)
class KNewFileMenuPrivate::RealFileOrDirStrategy : public KNewFileMenuPrivate::StrategyInterface
{
public:
    virtual void execute(const KNewFileMenuSingleton::Entry& entry);
};

bool KNewFileMenuPrivate::StrategyInterface::checkSourceExists(const QString& src)
{
    if (!QFile::exists(src)) {
        kWarning(1203) << src << "doesn't exist" ;
        KMessageBox::sorry(m_parentWidget, i18n("<qt>The template file <b>%1</b> does not exist.</qt>", src));
        return false;
    }
    return true;
}

void KNewFileMenuPrivate::UrlDesktopFileStrategy::execute(const KNewFileMenuSingleton::Entry& entry)
{
    // entry.comment contains i18n("Enter link to location (URL):"). JFYI :)
    KNameAndUrlInputDialog dlg(i18n("File name:"), entry.comment, m_popupUrls.first(), m_parentWidget);
    // TODO dlg.setCaption(i18n(...));
    if (!dlg.exec())
        return;

    m_chosenFileName = dlg.name();
    const KUrl linkUrl = dlg.url(); // the url to put in the file
    if (m_chosenFileName.isEmpty() || linkUrl.isEmpty())
        return;

    // It's a "URL" desktop file; we need to make a temp copy of it, to modify it
    // before copying it to the final destination [which could be a remote protocol]
    KTemporaryFile tmpFile;
    tmpFile.setAutoRemove(false); // done below
    if (!tmpFile.open()) {
        kError() << "Couldn't create temp file!";
        return;
    }

    if (!checkSourceExists(entry.templatePath)) {
        return;
    }

    // First copy the template into the temp file
    QFile file(entry.templatePath);
    if (!file.open(QIODevice::ReadOnly)) {
        kError() << "Couldn't open template" << entry.templatePath;
        return;
    }
    const QByteArray data = file.readAll();
    tmpFile.write(data);
    const QString tempFileName = tmpFile.fileName();
    Q_ASSERT(!tempFileName.isEmpty());
    tmpFile.close();

    KDesktopFile df(tempFileName);
    KConfigGroup group = df.desktopGroup();
    group.writeEntry("Icon", KProtocolInfo::icon(linkUrl.protocol()));
    group.writePathEntry("URL", linkUrl.prettyUrl());
    df.sync();
    m_src = tempFileName;
    m_tempFileToDelete = tempFileName;
}

void KNewFileMenuPrivate::SymLinkStrategy::execute(const KNewFileMenuSingleton::Entry& entry)
{
    KNameAndUrlInputDialog dlg(i18n("File name:"), entry.comment, m_popupUrls.first(), m_parentWidget);
    // TODO dlg.setCaption(i18n(...));
    if (!dlg.exec())
        return;
    m_chosenFileName = dlg.name(); // no path
    KUrl linkUrl = dlg.url(); // the url to put in the file
    if (m_chosenFileName.isEmpty() || linkUrl.isEmpty())
        return;

    if (linkUrl.isRelative())
        m_src = linkUrl.url();
    else if (linkUrl.isLocalFile())
        m_src = linkUrl.toLocalFile();
    else {
        KMessageBox::sorry(m_parentWidget, i18n("Basic links can only point to local files or directories.\nPlease use \"Link to Location\" for remote URLs."));
        return;
    }
}

void KNewFileMenuPrivate::OtherDesktopFileStrategy::execute(const KNewFileMenuSingleton::Entry& entry)
{
    if (!checkSourceExists(entry.templatePath)) {
        return;
    }

    KUrl::List::const_iterator it = m_popupUrls.constBegin();
    for (; it != m_popupUrls.constEnd(); ++it)
    {
        //kDebug(1203) << "first arg=" << entry.templatePath;
        //kDebug(1203) << "second arg=" << (*it).url();
        //kDebug(1203) << "third arg=" << entry.text;
        QString text = entry.text;
        text.remove("..."); // the ... is fine for the menu item but not for the default filename

        KUrl defaultFile(*it);
        defaultFile.addPath(KIO::encodeFileName(text));
        if (defaultFile.isLocalFile() && QFile::exists(defaultFile.toLocalFile()))
            text = KIO::RenameDialog::suggestName(*it, text);

        const KUrl templateUrl(entry.templatePath);
        KPropertiesDialog dlg(templateUrl, *it, text, m_parentWidget);
        dlg.exec();
    }
    // We don't set m_src here -> there will be no copy, we are done.
}

void KNewFileMenuPrivate::RealFileOrDirStrategy::execute(const KNewFileMenuSingleton::Entry& entry)
{
    // The template is not a desktop file
    // Show the small dialog for getting the destination filename
    QString text = entry.text;
    text.remove("..."); // the ... is fine for the menu item but not for the default filename

    KUrl defaultFile(m_popupUrls.first());
    defaultFile.addPath(KIO::encodeFileName(text));
    if (defaultFile.isLocalFile() && QFile::exists(defaultFile.toLocalFile()))
        text = KIO::RenameDialog::suggestName(m_popupUrls.first(), text);

    bool ok;
    const QString name = KInputDialog::getText(QString(), entry.comment,
                                               text, &ok, m_parentWidget);
    if (ok) {
        m_chosenFileName = name;
        m_src = entry.templatePath;
    }
}

void KNewFileMenuPrivate::_k_slotActionTriggered(QAction* action)
{
    q->trigger(); // was for kdesktop's slotNewMenuActivated() in kde3 times. Can't hurt to keep it...

    if (action == m_newDirAction) {
        q->createDirectory();
        return;
    }
    const int id = action->data().toInt();
    Q_ASSERT(id > 0);

    KNewFileMenuSingleton* s = kNewMenuGlobals;
    const KNewFileMenuSingleton::Entry entry = s->templatesList->at(id - 1);
    //kDebug(1203) << "sFile=" << sFile;

    const bool createSymlink = entry.templatePath == "__CREATE_SYMLINK__";
    KNewFileMenuPrivate::StrategyInterface* strategy = 0;

    if (createSymlink) {
        strategy = new KNewFileMenuPrivate::SymLinkStrategy;
    } else if (KDesktopFile::isDesktopFile(entry.templatePath)) {
        KDesktopFile df(entry.templatePath);
        if (df.readType() == "Link") {
            strategy = new KNewFileMenuPrivate::UrlDesktopFileStrategy;
        } else { // any other desktop file (Device, App, etc.)
            strategy = new KNewFileMenuPrivate::OtherDesktopFileStrategy;
        }
    } else {
        strategy = new KNewFileMenuPrivate::RealFileOrDirStrategy;
    }
    strategy->setParentWidget(m_parentWidget);
    strategy->setPopupFiles(m_popupFiles);
    strategy->execute(entry);
    m_tempFileToDelete = strategy->tempFileToDelete();
    const QString src = strategy->sourceFileToCopy();
    const QString chosenFileName = strategy->chosenFileName();
    delete strategy;

    if (src.isEmpty())
        return;
    KUrl uSrc(src);

    if (uSrc.isLocalFile()) {
        // In case the templates/.source directory contains symlinks, resolve
        // them to the target files. Fixes bug #149628.
        KFileItem item(uSrc, QString(), KFileItem::Unknown);
        if (item.isLink())
            uSrc.setPath(item.linkDest());
    }

    // The template is not a desktop file [or it's a URL one]
    // Copy it.
    KUrl::List::const_iterator it = m_popupFiles.constBegin();
    for (; it != m_popupFiles.constEnd(); ++it)
    {
        KUrl dest(*it);
        dest.addPath(KIO::encodeFileName(chosenFileName));

        KUrl::List lstSrc;
        lstSrc.append(uSrc);
        KIO::Job* kjob;
        if (createSymlink) {
            kjob = KIO::symlink(src, dest);
            // This doesn't work, FileUndoManager registers new links in copyingLinkDone,
            // which KIO::symlink obviously doesn't emit... Needs code in FileUndoManager.
            //KIO::FileUndoManager::self()->recordJob(KIO::FileUndoManager::Link, lstSrc, dest, kjob);
        } else {
            //kDebug(1203) << "KIO::copyAs(" << uSrc.url() << "," << dest.url() << ")";
            KIO::CopyJob * job = KIO::copyAs(uSrc, dest);
            job->setDefaultPermissions(true);
            kjob = job;
            KIO::FileUndoManager::self()->recordJob(KIO::FileUndoManager::Copy, lstSrc, dest, job);
        }
        kjob->ui()->setWindow(m_parentWidget);
        QObject::connect(kjob, SIGNAL(result(KJob*)),
                         q, SLOT(slotResult(KJob*)));
    }
}

void KNewFileMenu::slotResult(KJob * job)
{
    if (job->error()) {
        static_cast<KIO::Job*>(job)->ui()->showErrorMessage();
    } else {
        // Was this a copy or a mkdir?
        KIO::CopyJob* copyJob = ::qobject_cast<KIO::CopyJob*>(job);
        if (copyJob) {
            const KUrl destUrl = copyJob->destUrl();
            const KUrl localUrl = KIO::NetAccess::mostLocalUrl(destUrl, d->m_parentWidget);
            if (localUrl.isLocalFile()) {
                // Normal (local) file. Need to "touch" it, kio_file copied the mtime.
                (void) ::utime(QFile::encodeName(localUrl.toLocalFile()), 0);
            }
            emit fileCreated(destUrl);
        } else if (KIO::SimpleJob* simpleJob = ::qobject_cast<KIO::SimpleJob*>(job)) {
            // Can be mkdir or symlink
            if (simpleJob->property("isMkdirJob").toBool() == true) {
                kDebug() << "Emit directoryCreated" << simpleJob->url();
                emit directoryCreated(simpleJob->url());
            } else {
                emit fileCreated(simpleJob->url());
            }
        }
    }
    if (!d->m_tempFileToDelete.isEmpty())
        QFile::remove(d->m_tempFileToDelete);
}

void KNewFileMenu::setPopupFiles(const KUrl::List& files)
{
    d->m_popupFiles = files;
    if (files.isEmpty()) {
        d->m_newMenuGroup->setEnabled(false);
    } else {
        KUrl firstUrl = files.first();
        if (KProtocolManager::supportsWriting(firstUrl)) {
            d->m_newMenuGroup->setEnabled(true);
            if (d->m_newDirAction) {
                d->m_newDirAction->setEnabled(KProtocolManager::supportsMakeDir(firstUrl)); // e.g. trash:/
            }
        } else {
            d->m_newMenuGroup->setEnabled(true);
        }
    }
}

KUrl::List KNewFileMenu::popupFiles() const
{
    return d->m_popupFiles;
}

void KNewFileMenu::setViewShowsHiddenFiles(bool b)
{
    d->m_viewShowsHiddenFiles = b;
}

void KNewFileMenu::setSupportedMimeTypes(const QStringList& mime)
{
    d->m_supportedMimeTypes = mime;
}

QStringList KNewFileMenu::supportedMimeTypes() const
{
    return d->m_supportedMimeTypes;
}

#include "knewfilemenu.moc"