using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using Rhino.Mocks;
using SharpTestsEx;
using Sun.Identity.Common;

namespace Fedlet.UnitTests
{
    [TestFixture]
    public class LoggerFactoryTests
    {
        [Test]
        public void GetLogger_before_SetFactory_should_return_instance_of_FedletLogger()
        {
            LoggerFactory.GetLogger<LoggerFactoryTests>().Should().Be.InstanceOf<EventLogLogger>();
        }

        [Test]
        public void SetFactory_should_replace_the_instance_of_the_static_factory_delegate()
        {
            LoggerFactory.SetFactory(type => null);
            LoggerFactory.GetLogger<LoggerFactoryTests>().Should().Be.Null();
        }

        [Test]
        public void SetFactory_should_set_non_null_logger()
        {
            ILogger mockLogger = MockRepository.GenerateMock<ILogger>();

            LoggerFactory.SetFactory(type => mockLogger);
            LoggerFactory.GetLogger<LoggerFactoryTests>().Should().Be(mockLogger);
        }
    }
}
