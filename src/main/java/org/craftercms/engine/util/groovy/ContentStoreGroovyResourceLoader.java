package org.craftercms.engine.util.groovy;

import java.net.MalformedURLException;
import java.net.URL;

import groovy.lang.GroovyResourceLoader;
import org.apache.commons.lang3.StringUtils;
import org.craftercms.core.util.UrlUtils;
import org.craftercms.engine.scripting.impl.GroovyScriptFactory;
import org.craftercms.engine.service.context.SiteContext;
import org.craftercms.engine.util.url.ContentStoreUrlStreamHandler;

/**
 * Implementation of {@link org.craftercms.engine.util.groovy.ContentStoreGroovyResourceLoader} that uses Crafter
 * Core's content store to load Groovy resources.
 *
 * @author avasquez
 */
public class ContentStoreGroovyResourceLoader implements GroovyResourceLoader {

    protected SiteContext context;
    protected ContentStoreUrlStreamHandler urlStreamHandler;
    protected String groovyResourcesUrlPrefix;

    public ContentStoreGroovyResourceLoader(SiteContext context, String groovyResourcesUrlPrefix) {
        this.context = context;
        this.urlStreamHandler = new ContentStoreUrlStreamHandler(context);
        this.groovyResourcesUrlPrefix = groovyResourcesUrlPrefix;
    }

    @Override
    public URL loadGroovySource(String filename) throws MalformedURLException {
        if (filename.contains(".")) {
            filename = filename.replace('.', '/');
        }
        if (!filename.endsWith(GroovyScriptFactory.GROOVY_FILE_EXTENSION)) {
            filename += "." + GroovyScriptFactory.GROOVY_FILE_EXTENSION;
        }
        if (StringUtils.isNotEmpty(groovyResourcesUrlPrefix)) {
            filename = UrlUtils.appendUrl(groovyResourcesUrlPrefix, filename);
        }

        if (context.getStoreService().exists(context.getContext(), filename)){
            return urlStreamHandler.createUrl(filename);
        } else {
            return null;
        }
    }

}
