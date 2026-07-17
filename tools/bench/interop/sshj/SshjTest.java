import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.sftp.RemoteResourceInfo;
import net.schmizz.sshj.sftp.SFTPClient;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;

import java.util.List;

/**
 * SFTP interop check against bssh-server using sshj (the SSH stack used by
 * Cyberduck and other Java tools). Uploads a file, downloads it back, and
 * prints timing; integrity is verified by the calling script with cmp.
 *
 * Args: port user keyPath localFile remoteUploadPath localDownloadPath listDir
 */
public class SshjTest {
    public static void main(String[] args) throws Exception {
        String host = "127.0.0.1";
        int port = Integer.parseInt(args[0]);
        String user = args[1];
        String keyPath = args[2];
        String localFile = args[3];
        String remoteUp = args[4];
        String localDown = args[5];
        String listDir = args[6];

        SSHClient ssh = new SSHClient();
        ssh.addHostKeyVerifier(new PromiscuousVerifier());
        ssh.connect(host, port);
        try {
            ssh.authPublickey(user, keyPath);
            System.out.println("NEGOTIATED " + ssh.getTransport().getClientVersion()
                    + " <-> " + ssh.getTransport().getServerVersion());
            SFTPClient sftp = ssh.newSFTPClient();

            List<RemoteResourceInfo> ls = sftp.ls(listDir);
            System.out.println("LS_ENTRIES " + ls.size());

            long t0 = System.nanoTime();
            sftp.put(localFile, remoteUp);
            long t1 = System.nanoTime();
            sftp.get(remoteUp, localDown);
            long t2 = System.nanoTime();

            long size = sftp.stat(remoteUp).getSize();
            System.out.println("REMOTE_SIZE " + size);
            System.out.printf("UPLOAD_MIBS %.0f%n", size / 1048576.0 / ((t1 - t0) / 1e9));
            System.out.printf("DOWNLOAD_MIBS %.0f%n", size / 1048576.0 / ((t2 - t1) / 1e9));

            sftp.rm(remoteUp);
            sftp.close();
        } finally {
            ssh.disconnect();
        }
        System.out.println("SSHJ_OK");
    }
}
