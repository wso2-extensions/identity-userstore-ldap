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

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.comparators.NormalizingComparator;
import org.apache.directory.api.ldap.model.schema.registries.ComparatorRegistry;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.loader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmIndex;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.ldap.server.exception.DirectoryServerException;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class CarbonDirectoryServiceFactory {

    /**
     * A logger for this class
     */
    private static final Logger LOG = LoggerFactory.getLogger(CarbonDirectoryServiceFactory.class);
    /*Partition cache size is expressed as number of entries*/
    private static final int PARTITION_CACHE_SIZE = 500;
    private static final int INDEX_CACHE_SIZE = 100;
    /**
     * The default factory returns stock instances of a apacheds service with smart defaults
     */
    public static final CarbonDirectoryServiceFactory DEFAULT = new CarbonDirectoryServiceFactory();
    /**
     * The apacheds service.
     */
    private DirectoryService directoryService;

    private String schemaZipStore;

    /* default access */

    @SuppressWarnings({"unchecked"})
    CarbonDirectoryServiceFactory() {

        try {
            // creating the instance here so that
            // we we can set some properties like access control, anon access
            // before starting up the service
            directoryService = new DefaultDirectoryService();

        } catch (Exception e) {
            String errorMessage = "Error in initializing the default directory service.";
            LOG.error(errorMessage);
            throw new RuntimeException(errorMessage, e);
        }
    }

    public void init(String name) throws Exception {

        this.schemaZipStore = System.getProperty("schema.zip.store.location");

        if (this.schemaZipStore == null) {
            throw new DirectoryServerException(
                    "Schema Jar repository is not set. Please set schema.jar.location property " +
                            "with proper schema storage");
        }

        if (directoryService != null && directoryService.isStarted()) {
            return;
        }

        build(name);
    }

    /**
     * Build the working apacheds
     *
     * @param name Name of the working directory.
     */
    private void buildWorkingDirectory(String name) throws IOException {

        String workingDirectory = System.getProperty("workingDirectory");

        if (workingDirectory == null) {
            workingDirectory = System.getProperty("java.io.tmpdir") + File.separator +
                    "server-work-" + name;
        }
        InstanceLayout instanceLayout = new InstanceLayout(workingDirectory);
        directoryService.setInstanceLayout(instanceLayout);
    }

    /**
     * Inits the schema and schema partition.
     *
     * @throws Exception If unable to extract schema files.
     */
    private void initSchema() throws Exception {

        File workingDirectory = directoryService.getInstanceLayout().getPartitionsDirectory();

        // Extract the schema on disk (a brand new one) and load the registries
        File schemaRepository = new File(workingDirectory, "schema");
        if (!schemaRepository.exists()) {
            SchemaLdifExtractor extractor =
                    new CarbonSchemaLdifExtractor(workingDirectory, new File(this.schemaZipStore));
            extractor.extractOrCopy();
        }

        SchemaLoader loader = new LdifSchemaLoader(schemaRepository);
        SchemaManager schemaManager = new DefaultSchemaManager(loader);

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        // Tell all the normalizer comparators that they should not normalize anything
        ComparatorRegistry comparatorRegistry = schemaManager.getComparatorRegistry();

        for (LdapComparator<?> comparator : comparatorRegistry) {
            if (comparator instanceof NormalizingComparator) {
                ((NormalizingComparator) comparator).setOnServer();
            }
        }

        directoryService.setSchemaManager(schemaManager);

        // Init the LdifPartition
        LdifPartition ldifPartition = new LdifPartition(directoryService.getSchemaManager(), directoryService
                .getDnFactory());
//        String workingDirectory = directoryService.getInstanceLayout().getRunDirectory().getPath();
        ldifPartition.setPartitionPath(new File(workingDirectory, "schema").toURI());

        SchemaPartition schemaPartition = new SchemaPartition(schemaManager);
        schemaPartition.setWrappedPartition(ldifPartition);
        directoryService.setSchemaPartition(schemaPartition);

        List<Throwable> errors = schemaManager.getErrors();

        if (!errors.isEmpty()) {
            throw new DirectoryServerException(I18n.err(I18n.ERR_317, Exceptions.printErrors(errors)));
        }
    }

    /**
     * Inits the system partition.
     *
     * @throws Exception the exception
     */
    private void initSystemPartition() throws Exception {
        // change the working apacheds to something that is unique
        // on the system and somewhere either under target apacheds
        // or somewhere in a temp area of the machine.

        // Inject the System Partition
        JdbmPartition systemPartition = new JdbmPartition(directoryService.getSchemaManager(), directoryService.getDnFactory());
        systemPartition.setId("system");
        systemPartition.setPartitionPath(new File(directoryService.getInstanceLayout().getPartitionsDirectory(),
                systemPartition.getId()).toURI());
        systemPartition.setSuffixDn(new Dn(ServerDNConstants.SYSTEM_DN));
        systemPartition.setSchemaManager(directoryService.getSchemaManager());

        Set indexedAttributes = new HashSet();
        indexedAttributes.add(new JdbmIndex(SchemaConstants.OBJECT_CLASS_AT, false));
        systemPartition.setIndexedAttributes(indexedAttributes);

        directoryService.setSystemPartition(systemPartition);
    }

    /**
     * Builds the apacheds server instance.
     *
     * @param name the instance name
     * @throws Exception In case if unable to extract schema or if an error occurred when building
     *                   the working directory.
     */
    private void build(String name) throws Exception {

        directoryService.setInstanceId(name);
        CacheService cacheService = new CacheService();
        cacheService.initialize(directoryService.getInstanceLayout(), name);

        directoryService.setCacheService(cacheService);

        buildWorkingDirectory(name);

        // Init the service now
        initSchema();
        // Disable the ChangeLog system
        directoryService.getChangeLog().setEnabled(false);
        directoryService.setDenormalizeOpAttrsEnabled(true);
        initSystemPartition();

        directoryService.startup();
    }

    public DirectoryService getDirectoryService() throws Exception {

        return directoryService;
    }

}
