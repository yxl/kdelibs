/*
    Copyright 2011 Dave Vasilevsky <dave@vasilevsky.ca>

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
    License along with this library. If not, see <http://www.gnu.org/licenses/>.
*/

#include "iokitvolume.h"
#include "iokitdevice.h"

#include <QtCore/qdebug.h>

#include <IOKit/storage/IOMedia.h>
#include <DiskArbitration/DADisk.h>

using namespace Solid::Backends::IOKit;

Volume::Volume(IOKitDevice *device)
    : Block(device)
{
}

Volume::~Volume()
{

}

QString Volume::encryptedContainerUdi() const
{
    return QString(); // FIXME
}

qulonglong Volume::size() const
{
    return m_device->property(kIOMediaSizeKey).toULongLong();
}

QString Volume::uuid() const
{
    return m_device->property(kIOMediaUUIDKey).toString();
}

QString Volume::label() const
{
    return diskProp(kDADiskDescriptionVolumeNameKey).toString();
}

QString Volume::fsType() const
{
    return diskProp(kDADiskDescriptionVolumeKindKey).toString();
}

Solid::StorageVolume::UsageType Volume::usage() const
{
    return Solid::StorageVolume::Other; // FIXME
}

bool Volume::isIgnored() const
{
    return false; // FIXME
}

#include "backends/iokit/iokitvolume.moc"