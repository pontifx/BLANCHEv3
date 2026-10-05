import type { ModuleDefinition, ModuleDescriptor } from '../../shared/contracts';
import descriptorJson from './descriptor.json';
import { createBurpBridgeBackgroundController } from './background';

const descriptor = descriptorJson as ModuleDescriptor;

export const burpBridgeModule: ModuleDefinition = {
  descriptor,
  createBackgroundController({ logger, sessions, host }) {
    void sessions;
    void host;
    return createBurpBridgeBackgroundController({
      descriptor,
      logger
    });
  }
};
