package jcifs.smb1.dcerpc.msrpc;

import jcifs.smb1.dcerpc.DcerpcMessage;
import jcifs.smb1.dcerpc.ndr.NdrBuffer;
import jcifs.smb1.dcerpc.ndr.NdrException;
import jcifs.smb1.dcerpc.ndr.NdrObject;

/**
 * Server Service RPC interface implementation for remote server administration (SMB1).
 */
public class srvsvc {

    /**
     * Private constructor to prevent instantiation.
     */
    private srvsvc() {
    }

    /**
     * Gets the RPC interface syntax string.
     * @return the interface UUID and version
     */
    public static String getSyntax() {
        return "4b324fc8-1670-01d3-1278-5a47bf6ee188:3.0";
    }

    /**
     * Share information level 0 structure containing basic share information.
     */
    public static class ShareInfo0 extends NdrObject {

        /**
         * Default constructor for ShareInfo0.
         */
        public ShareInfo0() {
        }

        /**
         * The network name of the share.
         */
        public String netname;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(netname, 1);

            if (netname != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(netname);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _netnamep = _src.dec_ndr_long();

            if (_netnamep != 0) {
                _src = _src.deferred;
                netname = _src.dec_ndr_string();

            }
        }
    }

    /**
     * Container for ShareInfo0 structures.
     */
    public static class ShareInfoCtr0 extends NdrObject {

        /**
         * Default constructor for ShareInfoCtr0.
         */
        public ShareInfoCtr0() {
        }

        /**
         * The number of shares in the array.
         */
        /**
         * The number of shares in the array.
         */
        public int count;
        /**
         * Array of ShareInfo0 structures containing share information.
         */
        public ShareInfo0[] array;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(array, 1);

            if (array != null) {
                _dst = _dst.deferred;
                final int _arrays = count;
                _dst.enc_ndr_long(_arrays);
                final int _arrayi = _dst.index;
                _dst.advance(4 * _arrays);

                _dst = _dst.derive(_arrayi);
                for (int _i = 0; _i < _arrays; _i++) {
                    array[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _arrayp = _src.dec_ndr_long();

            if (_arrayp != 0) {
                _src = _src.deferred;
                final int _arrays = _src.dec_ndr_long();
                final int _arrayi = _src.index;
                _src.advance(4 * _arrays);

                if (array == null) {
                    if (_arrays < 0 || _arrays > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    array = new ShareInfo0[_arrays];
                }
                _src = _src.derive(_arrayi);
                for (int _i = 0; _i < _arrays; _i++) {
                    if (array[_i] == null) {
                        array[_i] = new ShareInfo0();
                    }
                    array[_i].decode(_src);
                }
            }
        }
    }

    /**
     * Share information level 1 structure containing extended share information.
     */
    public static class ShareInfo1 extends NdrObject {

        /**
         * Default constructor for ShareInfo1.
         */
        public ShareInfo1() {
        }

        /**
         * The network name of the share.
         */
        public String netname;
        /**
         * The type of the share.
         */
        public int type;
        /**
         * A comment or description of the share.
         */
        public String remark;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(netname, 1);
            _dst.enc_ndr_long(type);
            _dst.enc_ndr_referent(remark, 1);

            if (netname != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(netname);

            }
            if (remark != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(remark);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _netnamep = _src.dec_ndr_long();
            type = _src.dec_ndr_long();
            final int _remarkp = _src.dec_ndr_long();

            if (_netnamep != 0) {
                _src = _src.deferred;
                netname = _src.dec_ndr_string();

            }
            if (_remarkp != 0) {
                _src = _src.deferred;
                remark = _src.dec_ndr_string();

            }
        }
    }

    /**
     * Container for ShareInfo1 structures.
     */
    public static class ShareInfoCtr1 extends NdrObject {

        /**
         * Default constructor for ShareInfoCtr1.
         */
        public ShareInfoCtr1() {
        }

        /**
         * The number of shares in the array.
         */
        /**
         * The number of shares in the array.
         */
        public int count;
        /**
         * Array of ShareInfo1 structures containing share information.
         */
        public ShareInfo1[] array;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(array, 1);

            if (array != null) {
                _dst = _dst.deferred;
                final int _arrays = count;
                _dst.enc_ndr_long(_arrays);
                final int _arrayi = _dst.index;
                _dst.advance(12 * _arrays);

                _dst = _dst.derive(_arrayi);
                for (int _i = 0; _i < _arrays; _i++) {
                    array[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _arrayp = _src.dec_ndr_long();

            if (_arrayp != 0) {
                _src = _src.deferred;
                final int _arrays = _src.dec_ndr_long();
                final int _arrayi = _src.index;
                _src.advance(12 * _arrays);

                if (array == null) {
                    if (_arrays < 0 || _arrays > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    array = new ShareInfo1[_arrays];
                }
                _src = _src.derive(_arrayi);
                for (int _i = 0; _i < _arrays; _i++) {
                    if (array[_i] == null) {
                        array[_i] = new ShareInfo1();
                    }
                    array[_i].decode(_src);
                }
            }
        }
    }

    /**
     * Share information level 502 structure containing full share information including security.
     */
    public static class ShareInfo502 extends NdrObject {

        /**
         * Default constructor for ShareInfo502.
         */
        public ShareInfo502() {
        }

        /**
         * The network name of the share.
         */
        public String netname;
        /**
         * The type of the share.
         */
        public int type;
        /**
         * A comment or description of the share.
         */
        public String remark;
        /**
         * The share permissions.
         */
        public int permissions;
        /**
         * The maximum number of concurrent connections.
         */
        public int max_uses;
        /**
         * The current number of connections.
         */
        public int current_uses;
        /**
         * The local path of the share.
         */
        public String path;
        /**
         * The share password (if any).
         */
        public String password;
        /**
         * The size of the security descriptor.
         */
        public int sd_size;
        /**
         * The security descriptor bytes.
         */
        public byte[] security_descriptor;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_referent(netname, 1);
            _dst.enc_ndr_long(type);
            _dst.enc_ndr_referent(remark, 1);
            _dst.enc_ndr_long(permissions);
            _dst.enc_ndr_long(max_uses);
            _dst.enc_ndr_long(current_uses);
            _dst.enc_ndr_referent(path, 1);
            _dst.enc_ndr_referent(password, 1);
            _dst.enc_ndr_long(sd_size);
            _dst.enc_ndr_referent(security_descriptor, 1);

            if (netname != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(netname);

            }
            if (remark != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(remark);

            }
            if (path != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(path);

            }
            if (password != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(password);

            }
            if (security_descriptor != null) {
                _dst = _dst.deferred;
                final int _security_descriptors = sd_size;
                _dst.enc_ndr_long(_security_descriptors);
                final int _security_descriptori = _dst.index;
                _dst.advance(1 * _security_descriptors);

                _dst = _dst.derive(_security_descriptori);
                for (int _i = 0; _i < _security_descriptors; _i++) {
                    _dst.enc_ndr_small(security_descriptor[_i]);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            final int _netnamep = _src.dec_ndr_long();
            type = _src.dec_ndr_long();
            final int _remarkp = _src.dec_ndr_long();
            permissions = _src.dec_ndr_long();
            max_uses = _src.dec_ndr_long();
            current_uses = _src.dec_ndr_long();
            final int _pathp = _src.dec_ndr_long();
            final int _passwordp = _src.dec_ndr_long();
            sd_size = _src.dec_ndr_long();
            final int _security_descriptorp = _src.dec_ndr_long();

            if (_netnamep != 0) {
                _src = _src.deferred;
                netname = _src.dec_ndr_string();

            }
            if (_remarkp != 0) {
                _src = _src.deferred;
                remark = _src.dec_ndr_string();

            }
            if (_pathp != 0) {
                _src = _src.deferred;
                path = _src.dec_ndr_string();

            }
            if (_passwordp != 0) {
                _src = _src.deferred;
                password = _src.dec_ndr_string();

            }
            if (_security_descriptorp != 0) {
                _src = _src.deferred;
                final int _security_descriptors = _src.dec_ndr_long();
                final int _security_descriptori = _src.index;
                _src.advance(1 * _security_descriptors);

                if (security_descriptor == null) {
                    if (_security_descriptors < 0 || _security_descriptors > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    security_descriptor = new byte[_security_descriptors];
                }
                _src = _src.derive(_security_descriptori);
                for (int _i = 0; _i < _security_descriptors; _i++) {
                    security_descriptor[_i] = (byte) _src.dec_ndr_small();
                }
            }
        }
    }

    /**
     * Container for ShareInfo502 structures.
     */
    public static class ShareInfoCtr502 extends NdrObject {

        /**
         * Default constructor for ShareInfoCtr502.
         */
        public ShareInfoCtr502() {
        }

        /**
         * The number of shares in the array.
         */
        /**
         * The number of shares in the array.
         */
        public int count;
        /**
         * Array of ShareInfo502 structures containing share information.
         */
        public ShareInfo502[] array;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(count);
            _dst.enc_ndr_referent(array, 1);

            if (array != null) {
                _dst = _dst.deferred;
                final int _arrays = count;
                _dst.enc_ndr_long(_arrays);
                final int _arrayi = _dst.index;
                _dst.advance(40 * _arrays);

                _dst = _dst.derive(_arrayi);
                for (int _i = 0; _i < _arrays; _i++) {
                    array[_i].encode(_dst);
                }
            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            count = _src.dec_ndr_long();
            final int _arrayp = _src.dec_ndr_long();

            if (_arrayp != 0) {
                _src = _src.deferred;
                final int _arrays = _src.dec_ndr_long();
                final int _arrayi = _src.index;
                _src.advance(40 * _arrays);

                if (array == null) {
                    if (_arrays < 0 || _arrays > 0xFFFF) {
                        throw new NdrException(NdrException.INVALID_CONFORMANCE);
                    }
                    array = new ShareInfo502[_arrays];
                }
                _src = _src.derive(_arrayi);
                for (int _i = 0; _i < _arrays; _i++) {
                    if (array[_i] == null) {
                        array[_i] = new ShareInfo502();
                    }
                    array[_i].decode(_src);
                }
            }
        }
    }

    /**
     * RPC message for enumerating all shares on a server.
     */
    public static class ShareEnumAll extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x0f;
        }

        /**
         * The return value of the operation.
         */
        public int retval;
        /**
         * The name of the server.
         */
        public String servername;
        /**
         * The information level to return.
         */
        public int level;
        /**
         * The share information container.
         */
        public NdrObject info;
        /**
         * The preferred maximum length of returned data.
         */
        public int prefmaxlen;
        /**
         * The total number of entries.
         */
        public int totalentries;
        /**
         * The resume handle for enumeration.
         */
        public int resume_handle;

        /**
         * Constructs a ShareEnumAll request.
         * @param servername the server name
         * @param level the information level
         * @param info the information container
         * @param prefmaxlen the preferred maximum length
         * @param totalentries the total entries
         * @param resume_handle the resume handle
         */
        public ShareEnumAll(final String servername, final int level, final NdrObject info, final int prefmaxlen, final int totalentries,
                final int resume_handle) {
            this.servername = servername;
            this.level = level;
            this.info = info;
            this.prefmaxlen = prefmaxlen;
            this.totalentries = totalentries;
            this.resume_handle = resume_handle;
        }

        @Override
        public void encode_in(NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(servername, 1);
            if (servername != null) {
                _dst.enc_ndr_string(servername);

            }
            _dst.enc_ndr_long(level);
            final int _descr = level;
            _dst.enc_ndr_long(_descr);
            _dst.enc_ndr_referent(info, 1);
            if (info != null) {
                _dst = _dst.deferred;
                info.encode(_dst);

            }
            _dst.enc_ndr_long(prefmaxlen);
            _dst.enc_ndr_long(resume_handle);
        }

        @Override
        public void decode_out(NdrBuffer _src) throws NdrException {
            level = _src.dec_ndr_long();
            _src.dec_ndr_long(); /* union discriminant */
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                if (info == null) { /* YOYOYO */
                    info = new ShareInfoCtr0();
                }
                _src = _src.deferred;
                info.decode(_src);

            }
            totalentries = _src.dec_ndr_long();
            resume_handle = _src.dec_ndr_long();
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * RPC message for getting information about a specific share.
     */
    public static class ShareGetInfo extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x10;
        }

        /**
         * The return value of the operation.
         */
        public int retval;
        /**
         * The name of the server.
         */
        public String servername;
        /**
         * The name of the share.
         */
        public String sharename;
        /**
         * The information level to return.
         */
        public int level;
        /**
         * The share information.
         */
        public NdrObject info;

        /**
         * Constructs a ShareGetInfo request.
         * @param servername the server name
         * @param sharename the share name
         * @param level the information level
         * @param info the information container
         */
        public ShareGetInfo(final String servername, final String sharename, final int level, final NdrObject info) {
            this.servername = servername;
            this.sharename = sharename;
            this.level = level;
            this.info = info;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(servername, 1);
            if (servername != null) {
                _dst.enc_ndr_string(servername);

            }
            _dst.enc_ndr_string(sharename);
            _dst.enc_ndr_long(level);
        }

        @Override
        public void decode_out(NdrBuffer _src) throws NdrException {
            _src.dec_ndr_long(); /* union discriminant */
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                if (info == null) { /* YOYOYO */
                    info = new ShareInfo0();
                }
                _src = _src.deferred;
                info.decode(_src);

            }
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * Server information level 100 structure containing basic server information.
     */
    public static class ServerInfo100 extends NdrObject {

        /**
         * Default constructor for ServerInfo100.
         */
        public ServerInfo100() {
        }

        /**
         * The platform ID of the server.
         */
        public int platform_id;
        /**
         * The name of the server.
         */
        public String name;

        @Override
        public void encode(NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(platform_id);
            _dst.enc_ndr_referent(name, 1);

            if (name != null) {
                _dst = _dst.deferred;
                _dst.enc_ndr_string(name);

            }
        }

        @Override
        public void decode(NdrBuffer _src) throws NdrException {
            _src.align(4);
            platform_id = _src.dec_ndr_long();
            final int _namep = _src.dec_ndr_long();

            if (_namep != 0) {
                _src = _src.deferred;
                name = _src.dec_ndr_string();

            }
        }
    }

    /**
     * RPC message for retrieving server information at various detail levels.
     */
    public static class ServerGetInfo extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x15;
        }

        /**
         * The return value of the operation.
         */
        public int retval;
        /**
         * The name of the server.
         */
        public String servername;
        /**
         * The information level to return.
         */
        public int level;
        /**
         * The server information.
         */
        public NdrObject info;

        /**
         * Constructs a ServerGetInfo request.
         * @param servername the server name
         * @param level the information level
         * @param info the information container
         */
        public ServerGetInfo(final String servername, final int level, final NdrObject info) {
            this.servername = servername;
            this.level = level;
            this.info = info;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(servername, 1);
            if (servername != null) {
                _dst.enc_ndr_string(servername);

            }
            _dst.enc_ndr_long(level);
        }

        @Override
        public void decode_out(NdrBuffer _src) throws NdrException {
            _src.dec_ndr_long(); /* union discriminant */
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                if (info == null) { /* YOYOYO */
                    info = new ServerInfo100();
                }
                _src = _src.deferred;
                info.decode(_src);

            }
            retval = _src.dec_ndr_long();
        }
    }

    /**
     * Time of day information structure containing server time details.
     */
    public static class TimeOfDayInfo extends NdrObject {

        /**
         * Default constructor for TimeOfDayInfo.
         */
        public TimeOfDayInfo() {
        }

        /**
         * The time elapsed since 00:00:00, January 1, 1970 GMT.
         */
        public int elapsedt;
        /**
         * The number of milliseconds from the start of the current second.
         */
        public int msecs;
        /**
         * The current hour (0-23).
         */
        public int hours;
        /**
         * The current minute (0-59).
         */
        public int mins;
        /**
         * The current second (0-59).
         */
        public int secs;
        /**
         * The current hundredth of a second (0-99).
         */
        public int hunds;
        /**
         * The time zone offset from UTC in minutes.
         */
        public int timezone;
        /**
         * The time interval for each tick of the clock in 0.0001 seconds.
         */
        public int tinterval;
        /**
         * The current day of the month (1-31).
         */
        public int day;
        /**
         * The current month (1-12).
         */
        public int month;
        /**
         * The current year.
         */
        public int year;
        /**
         * The current day of the week (0-6, where 0 is Sunday).
         */
        public int weekday;

        @Override
        public void encode(final NdrBuffer _dst) throws NdrException {
            _dst.align(4);
            _dst.enc_ndr_long(elapsedt);
            _dst.enc_ndr_long(msecs);
            _dst.enc_ndr_long(hours);
            _dst.enc_ndr_long(mins);
            _dst.enc_ndr_long(secs);
            _dst.enc_ndr_long(hunds);
            _dst.enc_ndr_long(timezone);
            _dst.enc_ndr_long(tinterval);
            _dst.enc_ndr_long(day);
            _dst.enc_ndr_long(month);
            _dst.enc_ndr_long(year);
            _dst.enc_ndr_long(weekday);

        }

        @Override
        public void decode(final NdrBuffer _src) throws NdrException {
            _src.align(4);
            elapsedt = _src.dec_ndr_long();
            msecs = _src.dec_ndr_long();
            hours = _src.dec_ndr_long();
            mins = _src.dec_ndr_long();
            secs = _src.dec_ndr_long();
            hunds = _src.dec_ndr_long();
            timezone = _src.dec_ndr_long();
            tinterval = _src.dec_ndr_long();
            day = _src.dec_ndr_long();
            month = _src.dec_ndr_long();
            year = _src.dec_ndr_long();
            weekday = _src.dec_ndr_long();

        }
    }

    /**
     * RPC message for retrieving the server's time of day information.
     */
    public static class RemoteTOD extends DcerpcMessage {

        @Override
        public int getOpnum() {
            return 0x1c;
        }

        /**
         * The return value of the operation.
         */
        public int retval;
        /**
         * The name of the server.
         */
        public String servername;
        /**
         * The time of day information.
         */
        public TimeOfDayInfo info;

        /**
         * Constructs a RemoteTOD request.
         * @param servername the server name
         * @param info the time of day information container
         */
        public RemoteTOD(final String servername, final TimeOfDayInfo info) {
            this.servername = servername;
            this.info = info;
        }

        @Override
        public void encode_in(final NdrBuffer _dst) throws NdrException {
            _dst.enc_ndr_referent(servername, 1);
            if (servername != null) {
                _dst.enc_ndr_string(servername);

            }
        }

        @Override
        public void decode_out(final NdrBuffer _src) throws NdrException {
            final int _infop = _src.dec_ndr_long();
            if (_infop != 0) {
                if (info == null) { /* YOYOYO */
                    info = new TimeOfDayInfo();
                }
                info.decode(_src);

            }
            retval = _src.dec_ndr_long();
        }
    }
}
