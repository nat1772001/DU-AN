﻿using System;
using Castle.Windsor;
using Castle.MicroKernel.Registration;
using Castle.Windsor.Configuration.Interpreters;
using log4net;
using FX.Context;
using FX.Core;

namespace QL.Webapi
{
    public class Bootstrapper
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Bootstrapper));
        private static IWindsorContainer container;

        public static void InitializeContainer()
        {
            try
            {
                // Initialize Windsor
                container = new WindsorContainer(new XmlInterpreter());
                //container = new WindsorContainer(new XmlInterpreter(new ConfigResource("castle")));

                // Inititialize the static Windsor helper class.
                IoC.Initialize(container);

                // Add ICuyahogaContext to the container.
                container.Register(Component.For<IFXContext>()
                    .ImplementedBy<Context>()
                    .Named("FX.Context")
                    .LifeStyle.PerWebRequest
                );
            }
            catch (Exception ex)
            {
                log.Error("Error initializing application.", ex);
                throw;
            }
        }
    }
}