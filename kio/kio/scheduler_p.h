
#ifndef SCHEDULER_P_H
#define SCHEDULER_P_H
#include <QSet>

// #define SCHEDULER_DEBUG

class SlaveKeeper : public QObject
{
    Q_OBJECT
public:
    SlaveKeeper();
    void returnSlave(KIO::Slave *slave);
    KIO::Slave *takeSlaveForJob(KIO::SimpleJob *job);
    bool removeSlave(KIO::Slave *slave);
    QList<KIO::Slave *> allSlaves() const;

private:
    void scheduleGrimReaper();

private slots:
    void grimReaper();

private:
    QMultiHash<QString, KIO::Slave *> m_idleSlaves;
    QTimer m_grimTimer;
};


class HostQueue
{
public:
    int lowestSerial() const;

    bool isQueueEmpty() const { return m_queuedJobs.isEmpty(); }
    bool isEmpty() const { return m_queuedJobs.isEmpty() && m_runningJobs.isEmpty(); }
    int runningJobsCount() const { return m_runningJobs.count(); }
#ifdef SCHEDULER_DEBUG
    QList<KIO::SimpleJob *> runningJobs() const { return m_runningJobs.toList(); }
#endif
    bool isJobRunning(KIO::SimpleJob *job) const { return m_runningJobs.contains(job); }

    void queueJob(KIO::SimpleJob *job);
    KIO::SimpleJob *nextStartingJob();
    bool removeJob(KIO::SimpleJob *job);

    QList<KIO::Slave *> allSlaves() const;
private:
    QMap<int, KIO::SimpleJob *> m_queuedJobs;
    QSet<KIO::SimpleJob *> m_runningJobs;
};

class ConnectedSlaveQueue : public QObject
{
    Q_OBJECT
public:
    ConnectedSlaveQueue();

    bool queueJob(KIO::SimpleJob *job, KIO::Slave *slave);
    bool removeJob(KIO::SimpleJob *job);

    void addSlave(KIO::Slave *slave);
    bool removeSlave(KIO::Slave *slave);

    // KDE5: only one caller, for doubtful reasons. remove this if possible.
    bool isIdle(KIO::Slave *slave);
    bool isEmpty() const { return m_connectedSlaves.isEmpty(); }
    QList<KIO::Slave *> allSlaves() const { return m_connectedSlaves.keys(); }

private slots:
    void startRunnableJobs();
private:
    // note that connected slaves stay here when idle, they are not returned to SlaveKeeper
    QHash<KIO::Slave *, QList<KIO::SimpleJob *> > m_connectedSlaves;
    QSet<KIO::Slave *> m_runnableSlaves;
    QTimer m_startJobsTimer;
};


namespace KIO {
class SchedulerPrivate;
}

class SerialPicker
{
public:
    // note that serial number zero is the default value from job_p.h and invalid!
    SerialPicker()
     : m_offset(1) {}

    int next(int priority = 0)
    {
        if (m_offset >= m_jobsPerPriority) {
            m_offset = 1;
        }
        return m_offset++;
    }

    int changedPrioritySerial(int oldSerial, int newPriority) const;

private:
    static const int m_jobsPerPriority = 100000000;
    uint m_offset;
public:
    static const int maxSerial = m_jobsPerPriority * 20;
};


class ProtoQueue : public QObject
{
    Q_OBJECT
public:
    ProtoQueue(KIO::SchedulerPrivate *sp, int maxSlaves, int maxSlavesPerHost);
    ~ProtoQueue();

    void queueJob(KIO::SimpleJob *job);
    void changeJobPriority(KIO::SimpleJob *job, int newPriority);
    void removeJob(KIO::SimpleJob *job);
    KIO::Slave *createSlave(const QString &protocol, KIO::SimpleJob *job, const KUrl &url);
    bool removeSlave (KIO::Slave *slave);
    QList<KIO::Slave *> allSlaves() const;
    ConnectedSlaveQueue m_connectedSlaveQueue;

private slots:
    // start max one (non-connected) job and return
    void startAJob();

private:
    SerialPicker m_serialPicker;
    QTimer m_startJobTimer;
    QMap<int, HostQueue *> m_queuesBySerial;
    QHash<QString, HostQueue> m_queuesByHostname;
    KIO::SchedulerPrivate *m_schedPrivate;
    SlaveKeeper m_slaveKeeper;
    int m_maxConnectionsPerHost;
    int m_maxConnectionsTotal;
    int m_runningJobsCount;
};

#endif //SCHEDULER_P_H