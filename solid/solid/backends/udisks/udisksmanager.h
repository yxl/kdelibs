/*  Copyright 2010  Michael Zanetti <mzanetti@kde.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) version 3, or any
    later version accepted by the membership of KDE e.V. (or its
    successor approved by the membership of KDE e.V.), which shall
    act as a proxy defined in Section 6 of version 3 of the license.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public 
    License along with this library.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef UDISKSMANAGER_H
#define UDISKSMANAGER_H

#include "solid/ifaces/devicemanager.h"

#include <QtDBus/QDBusInterface>
#include <QtCore/QSet>

namespace Solid
{
namespace Backends
{
namespace UDisks
{
  
class UDisksManager : public Solid::Ifaces::DeviceManager
{
    Q_OBJECT
    
public:
    UDisksManager(QObject *parent);
    virtual QObject* createDevice(const QString& udi);
    virtual QStringList devicesFromQuery(const QString& parentUdi, Solid::DeviceInterface::Type type);
    virtual QStringList allDevices();
    virtual QSet< Solid::DeviceInterface::Type > supportedInterfaces() const;
    virtual QString udiPrefix() const;
    virtual ~UDisksManager();
    
private:
    QSet<Solid::DeviceInterface::Type> m_supportedInterfaces;
    QDBusInterface m_manager;

};

}
}
}
#endif // UDISKSMANAGER_H