package io.sensesecure.clamav4j;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Represents a ClamAV version. The ClamAV database is versioned in two ways -
 * the version number and the version time. Users of this class can choose their
 * preferred field of antivirus database versioning.
 */
public class ClamAVVersion {

    /**
     * Version of the ClamAV client.
     */
    private final String clamAvVersion;
    /**
     * Number of the database version. Higher number means newer version.
     */
    private final long databaseVersion;
    /**
     * Time when the database was updated. Higher number means newer version.
     */
    private final Date databaseTime;

    /**
     * Constructor.
     *
     * @param clamdResponse Response from the clamd VERSION command. Contains
     * '/'-separated version of the clamAV client, database and database
     * timestamp.
     */
    public ClamAVVersion(String clamdResponse) {
        String[] split = clamdResponse.split("\\/");
        this.clamAvVersion = split[0];
        this.databaseVersion = Long.parseLong(split[1]);
        try {
            this.databaseTime = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy", Locale.ENGLISH).parse(split[2]);
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * @return Version of the ClamAV client.
     */
    public String getClamAvVersion() {
        return clamAvVersion;
    }

    /**
     * @return Number of the database version. Higher number means newer
     * version.
     */
    public long getDatabaseVersion() {
        return databaseVersion;
    }

    /**
     * @return Time when the database was updated. Higher number means newer
     * version.
     */
    public Date getDatabaseTime() {
        return databaseTime;
    }

    /**
     * {@inheritDoc}
     *
     * @return ClamAVVersion String
     */
    @Override
    public String toString() {
        return "ClamAVVersion [clamAvVersion=" + clamAvVersion + ", databaseVersion=" + databaseVersion + ", databaseTime=" + databaseTime + "]";
    }
}
