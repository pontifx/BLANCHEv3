import type { ModuleDefinition, ModuleDescriptor } from '../../shared/contracts';
import descriptorJson from './descriptor.json';
import { createOsintSeedBackgroundController } from './background';

const descriptor = descriptorJson as ModuleDescriptor;

export const osintSeedModule: ModuleDefinition = {
  descriptor,
  createBackgroundController({ logger, sessions, host }) {
    void sessions;
    void host;
    return createOsintSeedBackgroundController({
      descriptor,
      logger
    });
  }
};
