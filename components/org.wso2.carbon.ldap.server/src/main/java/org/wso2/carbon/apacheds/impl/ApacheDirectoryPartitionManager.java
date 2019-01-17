/*
 *
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.apacheds.impl;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.xdbm.Index;
import org.apache.directory.shared.kerberos.KerberosAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.apacheds.AdminGroupInfo;
import org.wso2.carbon.apacheds.AdminInfo;
import org.wso2.carbon.apacheds.PartitionInfo;
import org.wso2.carbon.apacheds.PartitionManager;
import org.wso2.carbon.apacheds.PasswordAlgorithm;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.ldap.server.exception.DirectoryServerException;

import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * ApacheDS implementation of LDAP server. Contains methods to manipulate LDAP partitions.
 */
class ApacheDirectoryPartitionManager implements PartitionManager {

    /*Partition cache size is expressed as number of entries*/
    private static final int PARTITION_CACHE_SIZE = 500;
    private static final Logger logger = LoggerFactory.getLogger(
            ApacheDirectoryPartitionManager.class);
    private DirectoryService directoryService = null;
    private String workingDirectory;

    public ApacheDirectoryPartitionManager(DirectoryService directoryService, String wd) {
        this.directoryService = directoryService;
        this.workingDirectory = wd;
    }

    private static void throwDirectoryServerException(String message, Throwable e)
            throws DirectoryServerException {

        logger.error(message, e);
        throw new DirectoryServerException(message, e);
    }

    private static void addObjectClasses(Entry serverEntry, List<String> objectClasses)
            throws DirectoryServerException {

        for (String objectClass : objectClasses) {
            try {
                serverEntry.add("objectClass", objectClass);
            } catch (LdapException e) {
                throwDirectoryServerException("Could not add class to partition " +
                        serverEntry.getDn().getName(), e);
            }
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    public void addPartition(PartitionInfo partitionInformation)
            throws DirectoryServerException {

        try {
            JdbmPartition partition = createNewPartition(partitionInformation.getPartitionId(),
                    partitionInformation.getRootDN());
            this.directoryService.addPartition(partition);

            CoreSession adminSession = this.directoryService.getAdminSession();

            if (!adminSession.exists(partition.getSuffixDn())) {

                addPartitionAttributes(partitionInformation.getRootDN(), partitionInformation.
                                getObjectClasses(), partitionInformation.getRealm(),
                        partitionInformation.getPreferredDomainComponent());

                // Create user ou
                addUserStoreToPartition(partition.getSuffixDn().getName());

                // Create group ou
                addGroupStoreToPartition(partition.getSuffixDn().getName());

                //Creates the shared groups ou
                addSharedGroupToPartition(partition.getSuffixDn().getName());

                /*do not create admin user and admin group because it is anyway checked and created
                 *in user core.*/

                // create tenant administrator entry at the time of tenant-partition created.
                addAdmin(partitionInformation.getPartitionAdministrator(), partition.getSuffixDn().getName(),
                        partitionInformation.getRealm(), partitionInformation.isKdcEnabled());
                addAdminGroup(partitionInformation.getPartitionAdministrator(), partition.getSuffixDn().getName());

                addAdminACLEntry(partitionInformation.getPartitionAdministrator().getAdminUserName(),
                        partition.getSuffixDn().getName());

                this.directoryService.sync();
            }


        } catch (Exception e) {
            String errorMessage = "Could not add the partition";
            logger.error(errorMessage, e);
            throw new DirectoryServerException(errorMessage, e);

        }
    }

    /**
     * @inheritDoc
     */
    @Override
    public boolean partitionDirectoryExists(String partitionID) throws DirectoryServerException {
        boolean partitionDirectoryExists = false;
        String partitionDirectoryName = this.workingDirectory + File.separator + partitionID;
        File partitionDirectory = new File(partitionDirectoryName);

        //if a partition directory exists,it should be initialized without creating a new partition.
        if (partitionDirectory.exists()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Partition directory - " + partitionDirectoryName + " already exists.");
            }

            partitionDirectoryExists = true;
        }
        return partitionDirectoryExists;
    }

    /**
     * @inheritDoc
     */
    @Override
    public boolean partitionInitialized(String partitionId) {
        Set<? extends Partition> partitions = this.directoryService.getPartitions();

        for (Partition partition : partitions) {
            if (partition.getId().equals(partitionId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritDoc
     */
    @Override
    public int getNumberOfPartitions() {
        int numOfPartitions = 0; //if no partition is created

        Set<? extends Partition> partitions = this.directoryService.getPartitions();

        numOfPartitions = partitions.size();

        return numOfPartitions;
    }

    /**
     * This method initializes a partition from existing partition directory.
     */
    @Override
    public void initializeExistingPartition(PartitionInfo partitionInfo) throws
            DirectoryServerException {

        JdbmPartition existingPartition;
        try {
            // Create a new partition with the given partition id
            existingPartition = new JdbmPartition(directoryService.getSchemaManager(), directoryService.getDnFactory());
            existingPartition.setId(partitionInfo.getPartitionId());
            existingPartition.setPartitionPath(new File(this.workingDirectory, partitionInfo.getPartitionId()).toURI());
            existingPartition.setSuffixDn(new Dn(partitionInfo.getRootDN()));
            existingPartition.setCacheSize(PARTITION_CACHE_SIZE);
            existingPartition.setSchemaManager(directoryService.getSchemaManager());
            if (logger.isDebugEnabled()) {
                logger.debug("Partition" + partitionInfo.getPartitionId() +
                        " created from existing partition directory.");
            }

        } catch (Exception e) {
            logger.error("Error in creating partition from existing partition directory.", e);
            throw new DirectoryServerException("Error in creating partition from existing partition directory.", e);
        }
        /**
         *Initialize the existing partition in the directory service.
         */

        try {
            this.directoryService.addPartition(existingPartition);
            this.directoryService.sync();

            if (logger.isDebugEnabled()) {
                logger.debug("Partition" + partitionInfo.getPartitionId() +
                        " added to directory service.");
            }

        } catch (Exception e) {
            logger.error("Error in initializing partition in directory service", e);
            throw new DirectoryServerException("Error in initializing partition in directory service", e);
        }


    }

    /**
     * @inheritDoc
     */
    @Override
    public void removePartition(String partitionSuffix)
            throws DirectoryServerException {

        Partition partition = getPartition(partitionSuffix);

        if (partition == null) {
            String msg = "Error deleting partition. Could not find a partition with suffix " +
                    partitionSuffix;
            logger.error(msg);
            throw new DirectoryServerException(msg);
        }

        try {
            this.directoryService.removePartition(partition);
        } catch (Exception e) {
            String msg = "Unable to delete partition with suffix " + partitionSuffix;
            logger.error(msg, e);
            throw new DirectoryServerException("Unable to delete partition with suffix " +
                    partitionSuffix, e);
        }
    }

    @Override
    public void removeAllPartitions() throws DirectoryServerException {
        Set<? extends Partition> partitions = this.directoryService.getPartitions();

        for (Partition partition : partitions) {
//            if (!"schema".equalsIgnoreCase(partition.getId())) {

                try {

                    if (logger.isDebugEnabled()) {
                        logger.debug("Removing partition with id - " + partition.getId() + " suffix - " +
                                partition.getSuffixDn().getName());
                    }

                    this.directoryService.removePartition(partition);
                } catch (Exception e) {
                    String msg = "Unable to remove partition with id " + partition.getId() +
                            " with suffix " + partition.getSuffixDn().getName();
                    logger.error(msg, e);
                    throw new DirectoryServerException(msg, e);
                }
//            }
        }
    }

    /**
     * @inheritDoc
     */
    @Override
    public void synchronizePartitions()
            throws DirectoryServerException {

        try {

            this.directoryService.sync();
            List<Interceptor> interceptors = this.directoryService.getInterceptors();
            for (Interceptor interceptor : interceptors) {
                interceptor.init(this.directoryService);
            }

        } catch (Exception e) {
            throw new DirectoryServerException("Unable to sync partitions. ", e);
        }

    }

    private void addAccessControlAttributes(Entry serverEntry)
            throws LdapException {
        serverEntry.add("administrativeRole", "accessControlSpecificArea");
    }

    private void addPartitionAttributes(String partitionDN, List<String> objectClasses,
                                        String realm, String dc)
            throws DirectoryServerException {

        try {
            Dn adminDN = new Dn(partitionDN);
            Entry serverEntry = this.directoryService.newEntry(adminDN);

            addObjectClasses(serverEntry, objectClasses);

            serverEntry.add("o", realm);

            if (dc == null) {
                logger.warn("Domain component not found for partition with DN - " + partitionDN +
                        ". Not setting domain component.");
            } else {
                serverEntry.add("dc", dc);
            }

            addAccessControlAttributes(serverEntry);

            this.directoryService.getAdminSession().add(serverEntry);

        } catch (Exception e) {

            String msg = "Could not add partition attributes for partition - " + partitionDN;
            throwDirectoryServerException(msg, e);
        }

    }

    private void addUserStoreToPartition(String partitionSuffixDn)
            throws DirectoryServerException {

        try {
            Dn usersDN = new Dn("ou=Users," + partitionSuffixDn);
            Entry usersEntry = this.directoryService.newEntry(usersDN);
            usersEntry.add("objectClass", "organizationalUnit", "top");
            usersEntry.add("ou", "Users");

            this.directoryService.getAdminSession().add(usersEntry);

        } catch (LdapInvalidDnException e) {
            String msg = "Could not add user store to partition - " + partitionSuffixDn +
                    ". Cause - partition domain name is not valid.";
            throwDirectoryServerException(msg, e);

        } catch (LdapException e) {
            String msg = "Could not add user store to partition - " + partitionSuffixDn;
            throwDirectoryServerException(msg, e);
        } catch (Exception e) {
            String msg = "Could not add user store to partition admin session. - " +
                    partitionSuffixDn;
            throwDirectoryServerException(msg, e);
        }

    }

    private void addGroupStoreToPartition(String partitionSuffixDn)
            throws DirectoryServerException {

        Entry groupsEntry;
        try {

            Dn groupsDN = new Dn("ou=Groups," + partitionSuffixDn);

            groupsEntry = this.directoryService.newEntry(groupsDN);
            groupsEntry.add("objectClass", "organizationalUnit", "top");
            groupsEntry.add("ou", "Groups");

            this.directoryService.getAdminSession().add(groupsEntry);
        } catch (LdapException e) {
            String msg = "Could not add group store to partition - " + partitionSuffixDn;
            throwDirectoryServerException(msg, e);
        } catch (Exception e) {
            String msg = "Could not add group store to partition admin session. - " +
                    partitionSuffixDn;
            throwDirectoryServerException(msg, e);
        }

    }

    private void addSharedGroupToPartition(String partitionSuffixDn) throws DirectoryServerException {
        Entry groupsEntry;
        try {

            Dn groupsDN = new Dn("ou=SharedGroups," + partitionSuffixDn);

            groupsEntry = this.directoryService.newEntry(groupsDN);
            groupsEntry.add("objectClass", "organizationalUnit", "top");
            groupsEntry.add("ou", "SharedGroups");

            this.directoryService.getAdminSession().add(groupsEntry);
        } catch (LdapException e) {
            String msg = "Could not add shared group store to partition - " + partitionSuffixDn;
            throwDirectoryServerException(msg, e);
        } catch (Exception e) {
            String msg = "Could not add shared group store to partition admin session. - " +
                    partitionSuffixDn;
            throwDirectoryServerException(msg, e);
        }

    }

    private Partition getPartition(String partitionSuffix) {
        Set availablePartitions = this.directoryService.getPartitions();
        Partition partition;

        for (Object object : availablePartitions) {
            partition = (Partition) object;
            if (partition.getSuffixDn().getName().equals(partitionSuffix)) {
                return partition;
            }
        }

        return null;
    }

    private JdbmPartition createNewPartition(String partitionId, String partitionSuffix)
            throws DirectoryServerException {
        try {
            JdbmPartition partition = new JdbmPartition(directoryService.getSchemaManager(), directoryService.getDnFactory());
            String partitionDirectoryName = this.workingDirectory + File.separator + partitionId;

            partition.setId(partitionId);
            partition.setSuffixDn(new Dn(partitionSuffix));
//            .setPartitionPath(URI.create(partitionDirectoryName));
            partition.setPartitionPath(new File(partitionDirectoryName).toURI());


            Set<Index<?, String>> indexedAttrs = new HashSet<>();

            indexedAttrs.add(new JdbmIndex<Entry>("1.3.6.1.4.1.18060.0.4.1.2.3", true));
            indexedAttrs.add(new JdbmIndex<Entry>("1.3.6.1.4.1.18060.0.4.1.2.4", true));
            indexedAttrs.add(new JdbmIndex<Entry>("1.3.6.1.4.1.18060.0.4.1.2.5", true));
            indexedAttrs.add(new JdbmIndex<Entry>("1.3.6.1.4.1.18060.0.4.1.2.6", true));
            indexedAttrs.add(new JdbmIndex<Entry>("1.3.6.1.4.1.18060.0.4.1.2.7", true));

            indexedAttrs.add(new JdbmIndex<Entry>("ou", true));
            indexedAttrs.add(new JdbmIndex<Entry>("dc", true));
            indexedAttrs.add(new JdbmIndex<Entry>("objectClass", true));
            indexedAttrs.add(new JdbmIndex<Entry>("cn", true));
            indexedAttrs.add(new JdbmIndex<Entry>("uid", true));
            partition.setIndexedAttributes(indexedAttrs);

            String message = MessageFormat.format(
                    "Partition created with following attributes, partition id - {0}, Partition " +
                            "domain - {1}, Partition working directory {2}", partitionId,
                    partitionSuffix, partitionDirectoryName);

            if (logger.isDebugEnabled()) {
                logger.debug(message);
            }


            return partition;

        } catch (LdapInvalidDnException e) {
            String msg = "Could not add a new partition with partition id " + partitionId +
                    " and suffix " + partitionSuffix;
            logger.error(msg, e);
            throw new DirectoryServerException(msg, e);
        }
    }

    private void addAdminACLEntry(String adminUid, String tenantSuffix)
            throws DirectoryServerException {

        try {

            //add the permission entry
            Dn adminACLEntrydn = new Dn("cn=adminACLEntry," + tenantSuffix);
            Entry adminACLEntry = directoryService.newEntry(adminACLEntrydn);
            adminACLEntry.add("objectClass", "accessControlSubentry", "subentry", "top");
            adminACLEntry.add("cn", "adminACLEntry");

            String aclScript = "{ " +
                    "identificationTag \"adminACLEntryTag\", " +
                    "precedence 1, " +
                    "authenticationLevel simple, " +
                    "itemOrUserFirst userFirst: " +
                    "{ " +
                    "userClasses " +
                    "{ " +
                    "name { " +
                    "\"uid=" + adminUid + ",ou=Users," + tenantSuffix + "\" " +
                    "}  " +
                    "}, " +
                    "userPermissions " +
                    "{ " +
                    "{ " +
                    "protectedItems { entry, allUserAttributeTypesAndValues }, " +
                    "grantsAndDenials { " +
                    "grantBrowse, " +
                    "grantFilterMatch, " +
                    "grantModify, " +
                    "grantAdd, " +
                    "grantCompare, " +
                    "grantRename, " +
                    "grantRead, " +
                    "grantReturnDN, " +
                    "grantImport, " +
                    "grantInvoke, " +
                    "grantRemove, " +
                    "grantExport, " +
                    "grantDiscloseOnError " +
                    "} " +
                    "} " +
                    "} " +
                    "} " +
                    "}";

            adminACLEntry.add("prescriptiveACI", aclScript);
            adminACLEntry.add("subtreeSpecification", "{ }");

            directoryService.getAdminSession().add(adminACLEntry);

        } catch (LdapInvalidDnException e) {
            throwDirectoryServerException("Domain name invalid - cn=adminACLEntry," +
                    tenantSuffix, e);
        } catch (LdapException e) {
            throwDirectoryServerException("Unable to create ACL entry for user " + adminUid, e);
        } catch (Exception e) {
            throwDirectoryServerException(
                    "Unable to add ACL entry for user - " + adminUid +
                            " with DN - cn=adminACLEntry," + tenantSuffix, e);
        }

    }

    private void addAdminPassword(Entry adminEntry, String password,
                                  PasswordAlgorithm algorithm,
                                  final boolean kdcEnabled)
            throws DirectoryServerException {

        try {
            String passwordToStore = "{" + algorithm.getAlgorithmName() + "}";
            if (algorithm != PasswordAlgorithm.PLAIN_TEXT && !kdcEnabled) {
                MessageDigest md = MessageDigest.getInstance(algorithm.getAlgorithmName());
                md.update(password.getBytes());
                byte[] bytes = md.digest();
                String hash = Base64.encode(bytes);
                passwordToStore = passwordToStore + hash;

            } else {

                if (kdcEnabled) {
                    logger.warn(
                            "KDC enabled. Enforcing passwords to be plain text. Cause - KDC " +
                                    "cannot operate with hashed passwords.");
                }

                passwordToStore = password;
            }

            adminEntry.put("userPassword", passwordToStore.getBytes());

        } catch (NoSuchAlgorithmException e) {
            throwDirectoryServerException("Could not find matching hash algorithm - " +
                    algorithm.getAlgorithmName(), e);
        }

    }

    private void addAdminGroup(AdminInfo adminInfo, String partitionSuffix)
            throws DirectoryServerException {

        AdminGroupInfo groupInfo = adminInfo.getGroupInformation();

        if (groupInfo != null && StringUtils.contains(groupInfo.getAdminRoleName(),"/")) {
            String adminRole = groupInfo.getAdminRoleName();
            adminRole = adminRole.substring(adminRole.indexOf("/") + 1);
            groupInfo.setAdminRoleName(adminRole);
        }

        String domainName = "";
        try {

            if (groupInfo != null) {

                domainName = groupInfo.getGroupNameAttribute() + "=" +
                        groupInfo.getAdminRoleName() + "," + "ou=Groups," + partitionSuffix;

                Dn adminGroup = new Dn(domainName);
                Entry adminGroupEntry = directoryService.newEntry(adminGroup);
                addObjectClasses(adminGroupEntry, groupInfo.getObjectClasses());

                adminGroupEntry.add(groupInfo.getGroupNameAttribute(),
                        groupInfo.getAdminRoleName());
                adminGroupEntry.add(groupInfo.getMemberNameAttribute(),
                        adminInfo.getUsernameAttribute() + "=" + adminInfo.getAdminUserName() + "," + "ou=Users," +
                                partitionSuffix);
                directoryService.getAdminSession().add(adminGroupEntry);
            }

        } catch (LdapInvalidDnException e) {
            String msg = "Domain name invalid " + domainName;
            throwDirectoryServerException(msg, e);
        } catch (LdapException e) {
            throwDirectoryServerException("Could not add group entry - " + domainName, e);
        } catch (Exception e) {
            throwDirectoryServerException("Could not add group entry to admin session. DN - " +
                    domainName, e);
        }
    }

    private void addAdmin(AdminInfo adminInfo, String partitionSuffix, final String realm,
                          final boolean kdcEnabled) throws DirectoryServerException {

        if (adminInfo.getAdminUserName().contains("/")) {
            String admin = adminInfo.getAdminUserName();
            admin = admin.substring(admin.indexOf("/") + 1);
            adminInfo.setAdminUserName(admin);
        }

        String domainName = adminInfo.getUsernameAttribute() + "=" + adminInfo.getAdminUserName() + "," + "ou=Users," + partitionSuffix;

        try {
            Dn adminDn = new Dn(domainName);

            Entry adminEntry = directoryService.newEntry(adminDn);

            List<String> objectClasses = adminInfo.getObjectClasses();

            // Add Kerberose specific object classes
            objectClasses = new ArrayList<String>(adminInfo.getObjectClasses());
            objectClasses.add("krb5principal");
            objectClasses.add("krb5kdcentry");

            addObjectClasses(adminEntry, objectClasses);

            adminEntry.add(adminInfo.getUsernameAttribute(),
                    adminInfo.getAdminUserName());
            adminEntry.add("sn", adminInfo.getAdminLastName());
            adminEntry.add("givenName", adminInfo.getAdminCommonName());
            // setting admin full name as uid since 'cn' is a compulsory
            // attribute when constructing a
            // user entry.
            adminEntry.add("cn", adminInfo.getAdminUserName());

            if (!"mail".equals(adminInfo.getUsernameAttribute())) {
                adminEntry.add("mail", adminInfo.getAdminEmail());
            }

            String principal = adminInfo.getAdminUserName() + "/" + MultitenantConstants.SUPER_TENANT_DOMAIN_NAME + "@" + realm;
            adminEntry.put(KerberosAttribute.KRB5_PRINCIPAL_NAME_AT, principal);
            adminEntry.put(KerberosAttribute.KRB5_KEY_VERSION_NUMBER_AT, "0");

            addAdminPassword(adminEntry, adminInfo.getAdminPassword(),
                    adminInfo.getPasswordAlgorithm(), kdcEnabled);

            directoryService.getAdminSession().add(adminEntry);

        } catch (LdapInvalidDnException e) {
            throwDirectoryServerException("Domain name invalid " + domainName, e);
        } catch (LdapException e) {
            throwDirectoryServerException("Could not add entry to partition. DN - " +
                    domainName, e);
        } catch (Exception e) {
            throwDirectoryServerException("Could not add group entry to admin session. DN - " +
                    domainName, e);
        }

    }
}

